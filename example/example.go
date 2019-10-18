package main

import (
	"fmt"
	"github.com/evilsocket/islazy/fs"
	"github.com/evilsocket/islazy/str"
	"github.com/evilsocket/quijote/quijote"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/evilsocket/islazy/log"
	"github.com/gorilla/mux"
)

var (
	address = "127.0.0.1:8080"
)

func homeLink(w http.ResponseWriter, r *http.Request) {
	for param, values := range r.URL.Query() {
		fmt.Fprintf(w, "%s: %s", param, values)
	}
	// fmt.Fprintf(w, "%s", r.URL.RawQuery)
}

func main() {
	// log.Level = log.DEBUG
	log.DateFormat = "06-Jan-02"
	log.TimeFormat = "15:04:05"
	log.DateTimeFormat = "2006-01-02 15:04:05"
	log.Format = "{datetime} {level:color}{level:name}{reset} {message}"

	if err := log.Open(); err != nil {
		panic(err)
	}
	defer log.Close()

	policy := quijote.DefaultPolicy()
	policy.RulesPath = "rules"
	policy.DumpPath = "example/detections"
	// policy.BanMaxDetections = 25
	// policy.BanDuration = 10 * time.Millisecond
	policy.Ban = false

	engine, err := quijote.NewEngine(policy)
	if err != nil {
		log.Fatal("%v", err)
	}

	router := mux.NewRouter().StrictSlash(true)

	router.Use(engine.Middleware)

	router.HandleFunc("/", homeLink)

	go func() {
		time.Sleep(100 * time.Millisecond)
		log.Info("testing vectors ...")

		lines, err := fs.LineReader("example/vectors.txt")
		if err != nil {
			log.Fatal("%v", err)
		}

		passed := 0
		blocked := 0
		undetected := []string{}

		for line := range lines {
			if line = str.Trim(line); line != "" && line[0] != '#' {
				tmp, err := url.QueryUnescape(line)
				if err == nil && tmp != "" {
					line = tmp
				}

				endpoint, err := url.Parse("http://" + address + "/")
				parameters := url.Values{}
				parameters.Add("foo", line)
				endpoint.RawQuery = parameters.Encode()
				endpoint.Path = "/"

				resp, err := http.Get(endpoint.String())
				if err != nil {
					// handle error
					panic(err)
				} else {
					defer resp.Body.Close()
					_, _ = ioutil.ReadAll(resp.Body)
					// fmt.Printf("%s\n", body)

					if resp.StatusCode != policy.Redirect.Code {
						passed++
						log.Error("vector '%s' passed", line)
						undetected = append(undetected, line)
						// fmt.Println(hex.Dump([]byte(line)))
					} else {
						blocked++
					}
				}
			}
		}

		if passed == 0 {
			log.Info("%d passed, %d blocked", passed, blocked)
		} else {
			log.Error("%d passed, %d blocked", passed, blocked)
			fmt.Println()
			for _, v := range undetected {
				fmt.Printf("'%s'\n", v)
			}
			os.Exit(1)
		}
	}()

	log.Info("quijote protected API running on http://%s/ ...", address)
	log.Fatal("%v", http.ListenAndServe(address, router))
}
