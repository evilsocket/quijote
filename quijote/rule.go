package quijote

import (
	"bytes"
	"fmt"
	"github.com/evilsocket/islazy/log"
	"github.com/evilsocket/islazy/str"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type RuleScope string

var Scopes = map[string]RuleScope{
	"ip":      RuleScope("ip"),      // client ip address
	"method":  RuleScope("method"),  // http method
	"proto":   RuleScope("proto"),   // http protocol version
	"path":    RuleScope("path"),    // request path
	"query":   RuleScope("query"),   // request query parameters
	"headers": RuleScope("headers"), // request headers
	"body":    RuleScope("body"),    // raw request body if any
	"*":       RuleScope("*"),       // all of the above
}

type RuleType string

var Types = map[string]RuleType{
	"str": RuleType("str"),
	"re":  RuleType("re"),
	// "js":  RuleType("js"),
}

type Rule struct {
	Name        string   `yaml:"name"`           // rule name
	Description string   `yaml:"description"`    // description
	Enabled     bool     `yaml:"enabled"`        // is the rule enabled
	Type        RuleType `yaml:"type"`           // rule type (str or re)
	Scope       string   `yaml:"scope"`          // comma separated list of scopes
	Parts       []string `yaml:"parts" json:"-"` // the rule itself

	matchCb  func(data []byte) string
	compiled []*regexp.Regexp
	scopes   map[RuleScope]bool
}

type Match struct {
	// name of what matched
	Label string
	// specific rule pattern that matched
	Pattern string
	// content of what matched
	Data string
}

func LoadRule(fileName string) (*Rule, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	rule := &Rule{
		scopes: make(map[RuleScope]bool),
	}

	if err = yaml.Unmarshal(data, rule); err != nil {
		return nil, err
	}

	if _, found := Types[string(rule.Type)]; !found {
		return nil, fmt.Errorf("error parsing rule %s: '%s' is not a valid rule type", fileName, rule.Type)
	}

	for _, scope := range str.Comma(rule.Scope) {
		if _, found := Scopes[scope]; !found {
			return nil, fmt.Errorf("error parsing rule %s: '%s' is not a valid rule scope", fileName, scope)
		} else {
			rule.scopes[RuleScope(scope)] = true
		}
	}

	if rule.Type == "re" {
		rule.compiled = make([]*regexp.Regexp, 0)
		for _, expr := range rule.Parts {
			log.Debug("  compiling expression '%s'", expr)
			if compiled, err := regexp.Compile("(?ims)" + expr); err != nil {
				return nil, fmt.Errorf("error compiling rule %s:\n%s\n%s", fileName, expr, err)
			} else {
				rule.compiled = append(rule.compiled, compiled)
			}
		}
		rule.matchCb = rule.matchRE
	} else if rule.Type == "str" {
		rule.matchCb = rule.matchString
	}

	return rule, nil
}

func (rule *Rule) isTargeting(target string) bool {
	if _, found := rule.scopes["*"]; found {
		return true
	} else if _, found = rule.scopes[RuleScope(target)]; found {
		return true
	}
	return false
}

func (rule *Rule) checkFor(target string, data []byte) (Match, bool) {
	if rule.isTargeting(target) {
		if pattern := rule.matchCb(data); pattern != "" {
			return Match{
				Label:   fmt.Sprintf("http.%s", target),
				Pattern: pattern,
				Data:    string(data),
			}, true
		}
	}
	return Match{}, false
}

func (rule *Rule) Matches(req *http.Request, policy Policy) (match Match, matched bool) {
	if match, matched = rule.checkFor("method", []byte(req.Method)); matched {
		return
	} else if match, matched = rule.checkFor("proto", []byte(req.Proto)); matched {
		return
	} else if match, matched = rule.checkFor("path", []byte(req.URL.Path)); matched {
		return
	}

	if rule.isTargeting("query") {
		for param, values := range req.URL.Query() {
			if pattern := rule.matchCb([]byte(param)); pattern != "" {
				return Match{
					Label:   "http.query.param",
					Pattern: pattern,
					Data:    param,
				}, true
			}

			for _, value := range values {
				if pattern := rule.matchCb([]byte(value)); pattern != "" {
					return Match{
						Label:   fmt.Sprintf("http.query.param.%s", param),
						Pattern: pattern,
						Data:    value,
					}, true
				}

				decoded, _ := url.QueryUnescape(value)
				if pattern := rule.matchCb([]byte(decoded)); pattern != "" {
					return Match{
						Label:   fmt.Sprintf("http.query.param.%s", param),
						Pattern: pattern,
						Data:    decoded,
					}, true
				}
			}
		}
	}

	decoded, _ := url.QueryUnescape(req.URL.RawQuery)
	if match, matched = rule.checkFor("query", []byte(decoded)); matched {
		return
	}

	if rule.isTargeting("ip") {
		address := strings.Split(req.RemoteAddr, ":")[0]
		if pattern := rule.matchCb([]byte(address)); pattern != "" {
			return Match{
				Label:   "http.client",
				Pattern: pattern,
				Data:    address,
			}, true
		}

		if forwardedFor := req.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			if pattern := rule.matchCb([]byte(forwardedFor)); pattern != "" {
				return Match{
					Label:   "http.header.x-forwarded-for",
					Pattern: pattern,
					Data:    forwardedFor,
				}, true
			}
		}

		// https://support.cloudflare.com/hc/en-us/articles/206776727-What-is-True-Client-IP-
		if trueClient := req.Header.Get("True-Client-IP"); trueClient != "" {
			if pattern := rule.matchCb([]byte(trueClient)); pattern != "" {
				return Match{
					Label:   "http.header.true-client-ip",
					Pattern: pattern,
					Data:    trueClient,
				}, true
			}
		}
	}

	if rule.isTargeting("headers") {
		for name, values := range req.Header {
			for _, value := range values {
				if pattern := rule.matchCb([]byte(value)); pattern != "" {
					return Match{
						Label:   fmt.Sprintf("http.header.%s", name),
						Pattern: pattern,
						Data:    value,
					}, true
				}
			}
		}
	}

	if rule.isTargeting("body") && req.Body != nil && req.Body != http.NoBody {
		// NOTE: we use a LimitReader so we can't be DoSed
		if body, err := ioutil.ReadAll(io.LimitReader(req.Body, policy.MaxBodySize)); err == nil {
			// close and reset request to a buffer reader
			req.Body.Close()
			req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

			if pattern := rule.matchCb(body); pattern != "" {
				return Match{
					Label:   "http.body",
					Pattern: pattern,
					Data:    string(body),
				}, true
			}
		} else {
			log.Warning("error reading request body: %v", err)
		}
	}

	return Match{}, false
}

func (rule *Rule) matchString(data []byte) string {
	for _, elem := range rule.Parts {
		if bytes.Contains(data, []byte(elem)) {
			return string(elem)
		}
	}
	return ""
}

func (rule *Rule) matchRE(data []byte) string {
	for _, compiled := range rule.compiled {
		if compiled.Match(data) {
			return compiled.String()
		}
	}
	return ""
}
