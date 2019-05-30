package env

import (
	"os"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	var tests = []struct {
		value string
	}{
		{value: "foo"},
		{value: "bar"},
		{value: "baz"},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			key := strings.ToUpper(tt.value)
			if err := os.Setenv(key, tt.value); err != nil {
				t.Fatalf("failed to set env var %s for test: %s\n", key, err)
			}

			def := "default_value"
			if have, want := String(key, def), tt.value; have != want {
				t.Errorf("have %s, want %s", have, want)
			}
		})
	}

	// test default value
	def := "default_value"
	if have, want := String("TEST_DEFAULT", def), def; have != want {
		t.Errorf("have %s, want %s", have, want)
	}
}

func TestBool(t *testing.T) {
	var tests = []struct {
		env   string
		value bool
	}{
		{env: "TRUE", value: true},
		{env: "true", value: true},
		{env: "1", value: true},
		{env: "F", value: false},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			key := "TEST_BOOL"
			if err := os.Setenv(key, tt.env); err != nil {
				t.Fatalf("failed to set env var %s for test: %s\n", key, err)
			}

			def := false
			if have, want := Bool(key, def), tt.value; have != want {
				t.Errorf("have %v, want %v", have, want)
			}
		})
	}

	// test default value
	def := true
	if have, want := Bool("TEST_DEFAULT", def), def; have != want {
		t.Errorf("have %v, want %v", have, want)
	}
}

func TestInt(t *testing.T) {
	var tests = []struct {
		env   string
		value int
	}{
		{env: "0", value: 0},
		{env: "987", value: 987},
		{env: "-672", value: -672},
		{env: "68o8", value: 0},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			key := "TEST_INT"
			if err := os.Setenv(key, tt.env); err != nil {
				t.Fatalf("failed to set env var %s for test: %s\n", key, err)
			}

			def := 0
			if have, want := Int(key, def), tt.value; have != want {
				t.Errorf("have %v, want %v", have, want)
			}
		})
	}

	// test default value
	def := 42
	if have, want := Int("TEST_DEFAULT", def), def; have != want {
		t.Errorf("have %v, want %v", have, want)
	}
}
