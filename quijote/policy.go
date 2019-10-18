package quijote

import (
	"net/http"
	"time"
)

type CORS struct {
	Enabled        bool
	AllowedOrigin  string
	AllowedHeaders string
	AllowedMethods string
}

type Redirect struct {
	Code int
	URL  string
	Body string
}

type Policy struct {
	// path where to load yaml rule files from
	RulesPath string
	// if true, the middleware will block while all rules are executed, otherwise
	// the request will be pushed on a queue, allowed to go to the next middleware and
	// processed asynchronously
	Synchronous bool
	// number of workers if working in asynchronous mode, 0 for one worker per CPU core
	Workers int
	// max size of the request body for the io.LimitReader
	MaxBodySize int64
	// CORS rules
	CORS CORS
	// how to responde when running synchronously
	Redirect Redirect
	// wether or not to block a request if a detection is triggered
	Block bool
	// wether or not to report detections in the log
	Report bool
	// wether or not to ban the IP for BanDuration after BanMaxDetections detections
	Ban              bool
	BanMaxDetections uint64
	BanDuration      time.Duration
	// wether or not to dump detected requests to json files for further investigation
	Dump     bool
	DumpPath string
}

func DefaultPolicy() Policy {
	return Policy{
		RulesPath:        "/etc/quijote/rules/",
		Dump:             true,
		DumpPath:         "/var/log/quijote/detections/",
		Synchronous:      true,
		MaxBodySize:      1024 * 1024 * 50, // 50MB
		Block:            true,
		Report:           true,
		Ban:              true,
		BanMaxDetections: 5,
		BanDuration:      1 * time.Hour,
		Redirect: Redirect{
			Code: http.StatusForbidden,
			Body: "Request blocked by Quijote (http://github.com/evilsocket/quijote).",
		},
		CORS: CORS{
			Enabled:        true,
			AllowedOrigin:  "*",
			AllowedHeaders: "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization",
			AllowedMethods: "POST, GET, OPTIONS, PUT, DELETE",
		},
	}
}

func AsyncPolicy() Policy {
	return Policy{
		RulesPath:        "/etc/quijote/rules/",
		Dump:             true,
		DumpPath:         "/var/log/quijote/detections/",
		Synchronous:      false,
		Workers:          0,
		MaxBodySize:      1024 * 1024 * 50, // 50MB
		Block:            false,            // it's async, we can't block
		Report:           true,
		Ban:              true,
		BanMaxDetections: 3,
		BanDuration:      1 * time.Hour,
		Redirect: Redirect{
			Code: http.StatusForbidden,
			Body: "Request blocked by Quijote (http://github.com/evilsocket/quijote).",
		},
		CORS: CORS{
			Enabled:        true,
			AllowedOrigin:  "*",
			AllowedHeaders: "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization",
			AllowedMethods: "POST, GET, OPTIONS, PUT, DELETE",
		},
	}
}
