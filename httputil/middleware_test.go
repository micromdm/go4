package httputil

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPBasicAuth(t *testing.T) {
	var h http.Handler
	{
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		})

		h = (&BasicAuth{"groob", "groob", nil}).Middleware()(h)
	}

	var tests = []struct {
		username, password string
		expectedStatus     int
	}{
		0: {"groob", "groob", http.StatusOK},
		1: {"", "", http.StatusUnauthorized},
		2: {"", "groob", http.StatusUnauthorized},
		3: {"groob", "", http.StatusUnauthorized},
		4: {"foo", "bar", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			srv := httptest.NewServer(h)

			defer srv.Close()
			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(tt.username, tt.password)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if have, got := tt.expectedStatus, resp.StatusCode; have != got {
				t.Errorf("have %s, got %s", http.StatusText(have), http.StatusText(got))
			}

		})
	}

}

func TestHTTPDebugMiddleware(t *testing.T) {
	body := []byte("hello from client")
	response := "hello from server"
	debugOut := new(bytes.Buffer)
	var h http.Handler
	{
		// an example http handler
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Body.Close()

			if !bytes.Equal(body, got) {
				t.Errorf("http request body not equal to what was sent by client. have: %q, got: %q",
					string(body),
					string(got),
				)
			}
			fmt.Fprintf(w, response)
		})

		// with a nop logger
		nopLogger := func(...interface{}) error {
			return nil
		}

		// decorate with debug
		h = HTTPDebugMiddleware(debugOut, true, nopLogger)(h)

	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL, "text/plain", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// verify that the server sent back a correct body.
	out, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out, []byte(response)) {
		t.Errorf("response does not equal to what was sent by server. have: %q, got: %q",
			response,
			string(out),
		)
	}

	if !bytes.Contains(debugOut.Bytes(), body) {
		t.Errorf("debug output did not capture client request body")
	}

	if !bytes.Contains(debugOut.Bytes(), []byte(response)) {
		t.Errorf("debug output did not capture server response body")
	}
}
