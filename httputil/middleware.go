package httputil

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
)

// Middleware is a chainable decorator for HTTP Handlers.
type Middleware func(http.Handler) http.Handler

// Chain is a helper function for composing middlewares. Requests will
// traverse them in the order they're declared. That is, the first middleware
// is treated as the outermost middleware.
//
// Chain is identical to the go-kit helper for Endpoint Middleware.
func Chain(outer Middleware, others ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(others) - 1; i >= 0; i-- { // reverse
			next = others[i](next)
		}
		return outer(next)
	}
}

// ChainFrom wraps an HTTP Handler with the provided Middlewares.
func ChainFrom(h http.Handler, m ...Middleware) http.Handler {
	if len(m) > 0 {
		return Chain(m[0], m[1:]...)(h)
	}
	return h
}

// HTTPDebugMiddleware is a Middleware which prints the HTTP request and response to out.
// Use os.Stdout to print to standard out.
// If printBody is false, only the HTTP headers are printed.
// The Middleware requires a logger in case the request fails.
//
// Example: handler = HTTPDebugMiddleware(debugOut, true, nopLogger)(handler)
func HTTPDebugMiddleware(out io.Writer, printBody bool, logger func(...interface{}) error) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dump, err := httputil.DumpRequest(r, printBody)
			if err != nil {
				logger("err", err)
			}
			fmt.Fprintf(out, "---BEGIN Request---\n%s\n---END Request---\n", string(dump))
			recorder := httptest.NewRecorder()

			next.ServeHTTP(recorder, r)

			for key, values := range recorder.Header() {
				w.Header().Del(key)
				for _, value := range values {
					w.Header().Set(key, value)
				}
			}

			buf := new(bytes.Buffer)
			recorder.Body.WriteTo(io.MultiWriter(w, buf))
			recorder.Body = buf

			respDump, err := httputil.DumpResponse(recorder.Result(), printBody)
			if err != nil {
				logger("err", err)
			}

			fmt.Fprintf(out, "---BEGIN Response---\n%s\n---END Response---\n", string(respDump))
		})
	}
}

// BasicAuth implements Middleware for HTTP Basic Auth.
type BasicAuth struct {
	Username, Password string

	// Use to write a custom response to the client. If nil, a default WWW-Authenticate response is sent.
	FailedAuthResponseFunc func(w http.ResponseWriter)
}

// Middleware is an HTTP Middleware that checks for Basic Auth credentials.
func (auth *BasicAuth) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			usr, pass, ok := r.BasicAuth()
			if !ok || (usr != auth.Username || pass != auth.Password) {
				if auth.FailedAuthResponseFunc != nil {
					auth.FailedAuthResponseFunc(w)
				} else {
					w.Header().Set("WWW-Authenticate", `Basic realm="micromdm"`)
					http.Error(w, `{"error": "Not logged in."}`, http.StatusUnauthorized)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func enforceHSTS() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Forwarded-Proto") == "https" ||
				r.URL.Scheme == "https" ||
				(r.TLS != nil && r.TLS.HandshakeComplete) {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}
			next.ServeHTTP(w, r)
		})
	}
}
