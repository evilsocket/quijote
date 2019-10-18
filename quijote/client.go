package quijote

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is an object that holds the needed information about the request client.
type Client struct {
	// on some archs stuff used with the atomic package must be aligned
	// as first element otherwise unaligned memory exceptions might happen
	// when trying to perform atomic operations
	Detections uint64
	RemoteAddr string
	Key        string `json:"-"` // just used for indexing by the engine
	Addresses  map[string]string
	Banned     bool
	BannedAt   time.Time
}

// ParseClient returns a Client object parsed from the provided request.
func ParseClient(r *http.Request) Client {
	addr := strings.Split(r.RemoteAddr, ":")[0]
	cli := Client{
		RemoteAddr: addr,
		Key:        addr,
		Addresses:  make(map[string]string),
	}

	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		cli.Key += "::" + forwardedFor
		cli.Addresses["X-Forwarded-For"] = forwardedFor
	}
	// https://support.cloudflare.com/hc/en-us/articles/206776727-What-is-True-Client-IP-
	if trueClient := r.Header.Get("True-Client-IP"); trueClient != "" {
		cli.Key += "::" + trueClient
		cli.Addresses["True-Client-IP"] = trueClient
	}

	return cli
}

// String returns a string representation of the Client object indicating its real IP
// if different than its remote address.
func (cli Client) String() string {
	ip := cli.RemoteAddr
	for _, value := range cli.Addresses {
		if value != ip {
			ip = fmt.Sprintf("%s (%s)", value, ip)
		}
	}
	return ip
}
