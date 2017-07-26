package httputil_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/micromdm/go4/httputil"
)

func ExampleChain() {
	h := httputil.Chain(
		annotate("one"),
		annotate("two"),
		annotate("three"),
	)(myHandler())

	srv := httptest.NewServer(h)
	defer srv.Close()

	if _, err := http.Get(srv.URL); err != nil {
		panic(err)
	}

	// Output:
	// annotate:  one
	// annotate:  two
	// annotate:  three
}

func annotate(s string) httputil.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("annotate: ", s)
			next.ServeHTTP(w, r)
		})
	}
}

func myHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
}
