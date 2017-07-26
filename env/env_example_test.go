package env_test

import (
	"fmt"
	"os"

	"github.com/micromdm/go4/env"
)

func ExampleString() {
	addr := env.String("HTTP_ADDRESS", ":https")
	fmt.Printf("addr1: %s\n", addr)

	os.Setenv("HTTP_ADDRESS", "127.0.0.1:8080")

	addr = env.String("HTTP_ADDRESS", ":https")
	fmt.Printf("addr2: %s\n", addr)

	// Output:
	// addr1: :https
	// addr2: 127.0.0.1:8080
}
