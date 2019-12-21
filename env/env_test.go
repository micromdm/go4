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
		def   bool
		unset bool
	}{
		{env: "TRUE", def: true, value: true},
		{env: "TRUE", def: false, value: true},
		{env: "true", def: true, value: true},
		{env: "true", def: false, value: true},
		{env: "1", def: true, value: true},
		{env: "1", def: false, value: true},

		{env: "FALSE", def: true, value: false},
		{env: "FALSE", def: false, value: false},
		{env: "false", def: true, value: false},
		{env: "false", def: false, value: false},
		{env: "0", def: true, value: false},
		{env: "0", def: false, value: false},

		{env: "invalid", def: true, value: true},
		{env: "invalid", def: false, value: false},

		{unset: true, def: true, value: true },
		{unset: true, def: false, value: false },
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			key := "TEST_BOOL"
			if tt.unset {
				os.Unsetenv(key)
			}else{
				if err := os.Setenv(key, tt.env); err != nil {
					t.Fatalf("failed to set env var %s for test: %s\n", key, err)
				}
			}

			if have, want := Bool(key, tt.def), tt.value; have != want {
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
