package quijote

import (
	"encoding/json"
	"fmt"
	"github.com/evilsocket/islazy/async"
	"github.com/evilsocket/islazy/fs"
	"github.com/evilsocket/islazy/log"
	"github.com/evilsocket/islazy/tui"
	"github.com/kennygrant/sanitize"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"
)

type Engine struct {
	Middleware func(next http.Handler) http.Handler
	policy     Policy
	rules      map[string]*Rule
	queue      *async.WorkQueue
	offenders  sync.Map
}

func NewEngine(policy Policy) (*Engine, error) {
	eng := &Engine{
		policy:    policy,
		rules:     make(map[string]*Rule),
		offenders: sync.Map{},
	}

	log.Debug("loading quijote rules from %s ...", policy.RulesPath)

	err := fs.Glob(policy.RulesPath, "*.yml", func(fileName string) error {
		log.Debug("loading rule %s ...", fileName)
		if rule, err := LoadRule(fileName); err != nil {
			return err
		} else if _, found := eng.rules[rule.Name]; found {
			return fmt.Errorf("rule %s already registered", rule.Name)
		} else {
			eng.rules[rule.Name] = rule
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	log.Debug("loaded %d rules", len(eng.rules))

	if policy.Synchronous == false {
		eng.Middleware = eng.asyncMiddleware
		eng.queue = async.NewQueue(policy.Workers, func(arg async.Job) {
			// won't block, report only
			eng.doRules(nil, arg.(*http.Request))
		})
	} else {
		eng.Middleware = eng.syncMiddleware
	}

	return eng, nil
}

func (eng *Engine) log(format string, args ...interface{}) {
	if eng.policy.Report {
		format = tui.Yellow("[security]") + " " + format
		log.Info(format, args...)
	}
}

func (eng *Engine) doReport(r *http.Request, rule *Rule, match Match) {
	client := ParseClient(r)
	offender := (*Client)(nil)

	if obj, found := eng.offenders.Load(client.Key); found {
		offender = obj.(*Client)
	} else {
		log.Debug("new offender %v", client)
		offender = &client
		eng.offenders.Store(client.Key, offender)
	}

	atomic.AddUint64(&offender.Detections, 1)

	justBanned := false
	if eng.policy.Ban && offender.Detections > eng.policy.BanMaxDetections {
		offender.Banned = true
		offender.BannedAt = time.Now()
		justBanned = true
	}

	if eng.policy.Dump {
		dumpFilename := path.Join(eng.policy.DumpPath,
			fmt.Sprintf("%s_%s_%d.json",
				sanitize.BaseName(client.RemoteAddr),
				sanitize.BaseName(rule.Name),
				time.Now().UnixNano()))

		obj := map[string]interface{} {
			"detected_at": time.Now(),
			"rule": rule,
			"match": match,
			"client": offender,
			// "request": r,
		}

		if data, err := json.Marshal(obj); err == nil{
			if err := ioutil.WriteFile(dumpFilename, data, os.ModePerm); err != nil{
				log.Error("could not save %s: %v", dumpFilename, err)
			}
		} else {
			log.Error("could not dump %s: %v", dumpFilename, err)
		}
	}

	if justBanned {
		eng.log("%s on %s from %s (banned after %d detections) (%s)",
			rule.Name,
			tui.Bold(match.Label),
			offender.String(),
			offender.Detections,
			tui.Dim(match.Pattern))
	} else {
		eng.log("%s on %s from %s (%s)",
			rule.Name,
			tui.Bold(match.Label),
			offender.String(),
			tui.Dim(match.Pattern))
	}
	// log.Info("%v", match.Data)
}

func (eng *Engine) doResponse(w http.ResponseWriter, r *http.Request) {
	if w != nil {
		if eng.policy.Redirect.URL != "" {
			http.Redirect(w, r, eng.policy.Redirect.URL, http.StatusFound)
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(eng.policy.Redirect.Code)
			if _, err := w.Write([]byte(eng.policy.Redirect.Body)); err != nil {
				log.Error("error sending response: %v", err)
			}
		}
	}
}

func (eng *Engine) doRules(w http.ResponseWriter, r *http.Request) bool {
	for _, rule := range eng.rules {
		if rule.Enabled {
			// if there's a match, report, create a response and block the request
			if match, matched := rule.Matches(r, eng.policy); matched {
				eng.doReport(r, rule, match)
				eng.doResponse(w, r)
				return eng.policy.Block
			}
		}
	}
	return false
}

func (eng *Engine) doCORS(w http.ResponseWriter, r *http.Request) {
	if eng.policy.CORS.Enabled {
		w.Header().Add("X-Frame-Options", "DENY")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("X-XSS-Protection", "1; mode=block")
		w.Header().Add("Referrer-Policy", "same-origin")
		w.Header().Set("Access-Control-Allow-Origin", eng.policy.CORS.AllowedOrigin)
		w.Header().Add("Access-Control-Allow-Headers", eng.policy.CORS.AllowedHeaders)
		w.Header().Add("Access-Control-Allow-Methods", eng.policy.CORS.AllowedMethods)
	}
}

func (eng *Engine) isBanned(w http.ResponseWriter, r *http.Request) bool {
	client := ParseClient(r)
	offender := (*Client)(nil)

	// check if it's a known offender
	if obj, found := eng.offenders.Load(client.Key); found {
		// check if it's banned
		offender = obj.(*Client)
		if offender.Banned {
			if time.Since(offender.BannedAt) < eng.policy.BanDuration {
				log.Debug("[security] preventing %s from access as it's banned for %s",
					offender.String(),
					eng.policy.BanDuration-time.Since(offender.BannedAt))
				eng.doResponse(w, r)
				return true
			} else {
				log.Debug("[security] unbanning %s", offender.String())
				offender.Banned = false
				offender.Detections = 0
			}
		}
	}
	return false
}

func (eng *Engine) syncMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if eng.isBanned(w, r) == false {
			eng.doCORS(w, r)
			if block := eng.doRules(w, r); block == false {
				next.ServeHTTP(w, r)
			}
		}
	})
}

func (eng *Engine) asyncMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if eng.isBanned(w, r) == false {
			eng.doCORS(w, r)
			eng.queue.Add(async.Job(r))
			next.ServeHTTP(w, r)
		}
	})
}
