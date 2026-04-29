// Package principal extracts an optional human-readable label identifying the
// requester. Registry Gate itself does not authenticate clients; deployments
// that want attribution should put oauth2-proxy / Authelia / similar in front
// of Registry Gate, which will inject a header such as X-Forwarded-User.
package principal

import "net/http"

// LabelHeaders are inspected in order. The first non-empty value wins.
var LabelHeaders = []string{
	"X-Forwarded-User",   // oauth2-proxy / nginx-ingress / Authelia
	"X-Auth-Request-User", // oauth2-proxy alternative
	"X-Forwarded-Email",
}

// Label returns a free-form attribution label sourced from request headers,
// or "" when the request is unauthenticated (i.e. no upstream proxy is set up).
func Label(r *http.Request) string {
	for _, h := range LabelHeaders {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	return ""
}
