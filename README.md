<p align="center">
  <p align="center">
    <a href="https://github.com/evilsocket/quijote/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/evilsocket/quijote.svg?style=flat-square"></a>
    <a href="https://github.com/evilsocket/quijote/blob/master/LICENSE.md"><img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square"></a>
    <a href="https://travis-ci.org/evilsocket/quijote"><img alt="Travis" src="https://img.shields.io/travis/evilsocket/quijote/master.svg?style=flat-square"></a>
    <a href="https://goreportcard.com/report/github.com/evilsocket/quijote"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/evilsocket/quijote?style=flat-square&fuckgithubcache=1"></a>
    <a href="https://codecov.io/gh/evilsocket/quijote"><img alt="Code Coverage" src="https://img.shields.io/codecov/c/github/evilsocket/quijote/master.svg?style=flat-square"></a>
  </p>
</p>

**Quijote** is an highly configurable HTTP middleware for web and API services in Go, aimed at detecting the low hanging 
fruits in terms of web attacks and therefore providing a basic layer of security. It might not detect the most sophisticated 
attacks, but damn, it will never stop trying! (And it's better than nothing?)

**THIS PROJECT IS ACTIVELY BEING DEVELOPED, DO NOT USE IN PRODUCTION YET.*** 

... but if you can help improving the rules, the code base, writing tests or whatever, all PRs are welcome! :D

#### Rules

The engine is compatible with every framework that supports Go's standard middleware structure and it's based on yaml rules 
that can be ether raw strings or regular expressions (and in the near future, javascript rules too), so that you can use 
it to detect basic attacks:

```yaml
name: simple_xss_example
enabled: true
type: re
scope: '*'
parts:
  # just a tag
  - <[^>]+>
  # open tag with script
  - <[^>]+script:.+
```

Or as a blocklist for known offenders:

```yaml
name: simple_blocklist
enabled: true
type: str
scope: ip
parts:
  # some bad ip!
  - 10.2.3.4
  # another
  - 12.34.56.78
```

For some example rules check the `rules` folder (doh!).

#### Others

The engine can operate in synchronous mode, thus blocking the request while the rules are being checked, or asynchronously dispatch
a job on a queue without affecting the response times. It can also be configured a-la-fail2ban to ban offenders for a given amount of time after a given amount of attacks.

And it will also do [CORS](https://developer.mozilla.org/it/docs/Web/HTTP/CORS) for you!

#### Example

```go
import (
    ...
    "github.com/evilsocket/quijote/quijote"
    ...
)
...
...
// NOTE: this is for demonstration purposes and can just be replaced with:
// policy := quijote.DefaultPolicy()
policy := Policy{
	// where to load the rules from 
	RulesPath: "/etc/quijote/rules/",
	// whethere or not to dump detections as JSON files for further investigation
	Dump:     true,
	DumpPath: "/var/log/quijote/detections/",
	// which mode to operate
	Synchronous: true,
	// this is used with an io.LimitReader so that it is not possible to DoS what we're protecting
	// by sending huge payloads that the JSON parser will try to parse because almost nobody ever
	// thinks to limit it :)
	MaxBodySize: 1024 * 1024 * 50, // 50MB
	// log incidents
	Report: true,
	// ban for an hour offending clients after 5 detections
	Ban:              true,
	BanMaxDetections: 5,
	BanDuration:      1 * time.Hour,
	// block offending requests
	Block: true,
	// what to do after blocking a request
	Redirect: Redirect{
		Code: http.StatusForbidden,
		Body: "Request blocked by Quijote (http://github.com/evilsocket/quijote).",
	},
	// do basic CORS
	CORS: CORS{
		Enabled:        true,
		AllowedOrigin:  "*",
		AllowedHeaders: "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization",
		AllowedMethods: "POST, GET, OPTIONS, PUT, DELETE",
	},
}

engine, err := quijote.NewEngine(policy)
if err != nil {
    log.Fatal("%v", err)
}

// or whatever framework you fancy ...
router := mux.NewRouter()

// that's all it takes to integrate!
router.Use(engine.Middleware)

router.HandleFunc("/", whatever)
```

## License

`Quijote` is made with ♥  by [@evilsocket](https://twitter.com/evilsocket) and it is released under the GPL3 license.
