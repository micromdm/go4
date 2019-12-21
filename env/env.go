/*
Package env provides utility functions for loading environment variables with default values.

A common use of the env package is for combining flag with environment variables in a Go program.

Example:

	func main() {
		var (
			flProject = flag.String("http.addr", env.String("HTTP_ADDRESS", ":https"), "HTTP server address")
		)
		flag.Parse()
	}
*/
package env

import (
	"os"
	"strconv"
	"strings"
)

// String returns the environment variable value specified by the key parameter,
// otherwise returning a default value if set.
func String(key, def string) string {
	if env, ok := os.LookupEnv(key); ok {
		return env
	}
	return def
}

// Bool returns the environment variable value specified by the key parameter,
// otherwise returning a default value if set.
func Bool(key string, def bool) bool {
	switch env := os.Getenv(key); strings.ToLower(env) {
		case "true","yes","1": return true
		case "false","no","0": return false
	}
	return def
}

// Int returns the environment variable value specified by the key parameter,
// otherwise returning a default value if set.
func Int(key string, def int) int {
	env := os.Getenv(key)
	if i, err := strconv.Atoi(env); err == nil {
		return i
	}
	return def
}
