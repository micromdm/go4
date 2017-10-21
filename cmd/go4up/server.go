package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/pkg/errors"

	"github.com/micromdm/go4/env"
)

func runServer(args []string) error {
	flagset := flag.NewFlagSet("go4up", flag.ExitOnError)
	var (
		flAppName   = flagset.String("name", "example", "name of app")
		flOutputDir = flagset.String(
			"output",
			filepath.Join(gopath(), "src", "github.com", "micromdm", *flAppName),
			"path to output",
		)
	)

	flagset.Usage = usageFor(flagset, "go4up server [flags]")
	if err := flagset.Parse(args); err != nil {
		return err
	}

	dir := filepath.Join(*flOutputDir, "cmd", *flAppName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrapf(err, "creating output directory %s", dir)
	}

	tmplArgs := struct {
		Name string
	}{
		Name: *flAppName,
	}
	makefileBuf := new(bytes.Buffer)
	var makefileTmpl = template.Must(template.New("test").Parse(serverMakefileTemplate))
	if err := makefileTmpl.Execute(makefileBuf, tmplArgs); err != nil {
		return errors.Wrap(err, "execute makefile template")
	}

	serverBuf := new(bytes.Buffer)
	var serveTmpl = template.Must(template.New("serve").Parse(serverServeTemplate))
	if err := serveTmpl.Execute(serverBuf, tmplArgs); err != nil {
		return errors.Wrap(err, "execute serve.go template")
	}

	dockerfileBuf := new(bytes.Buffer)
	var dockerfileTmpl = template.Must(template.New("dockerfile").Parse(dockerfileTemplate))
	if err := dockerfileTmpl.Execute(dockerfileBuf, tmplArgs); err != nil {
		return errors.Wrap(err, "execute Dockerfile template")
	}

	gitignorePath := filepath.Join(*flOutputDir, ".gitignore")
	if err := ioutil.WriteFile(gitignorePath, []byte(gitignoreTemplate), 0644); err != nil {
		return errors.Wrapf(err, "writing file %s", gitignorePath)
	}

	makefilePath := filepath.Join(*flOutputDir, "Makefile")
	if err := ioutil.WriteFile(makefilePath, makefileBuf.Bytes(), 0644); err != nil {
		return errors.Wrapf(err, "writing file %s", makefilePath)
	}

	dockerfilePath := filepath.Join(*flOutputDir, "Dockerfile")
	if err := ioutil.WriteFile(dockerfilePath, dockerfileBuf.Bytes(), 0644); err != nil {
		return errors.Wrapf(err, "writing file %s", dockerfilePath)
	}

	mainPath := filepath.Join(dir, fmt.Sprintf("%s.go", *flAppName))
	if err := ioutil.WriteFile(mainPath, []byte(serverMainTemplate), 0644); err != nil {
		return errors.Wrapf(err, "writing file %s", mainPath)
	}

	servePath := filepath.Join(dir, "serve.go")
	if err := ioutil.WriteFile(servePath, serverBuf.Bytes(), 0644); err != nil {
		return errors.Wrapf(err, "writing file %s", servePath)
	}

	return nil

}

func gopath() string {
	home := env.String("HOME", "~/")
	return env.String("GOPATH", filepath.Join(home, "go"))
}

const serverMainTemplate = `package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/micromdm/go4/version"
)

func runVersion(args []string) error {
	version.PrintFull()
	return nil
}

func usageFor(fs *flag.FlagSet, short string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "USAGE\n")
		fmt.Fprintf(os.Stderr, "  %s\n", short)
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "FLAGS\n")
		w := tabwriter.NewWriter(os.Stderr, 0, 2, 2, ' ', 0)
		fs.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(w, "\t-%s %s\t%s\n", f.Name, f.DefValue, f.Usage)
		})
		w.Flush()
		fmt.Fprintf(os.Stderr, "\n")
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "USAGE\n")
	fmt.Fprintf(os.Stderr, "  %s <mode> --help\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "MODES\n")
	fmt.Fprintf(os.Stderr, "  serve        Run the server\n")
	fmt.Fprintf(os.Stderr, "  version      Print full version information\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "VERSION\n")
	fmt.Fprintf(os.Stderr, "  %s\n", version.Version().Version)
	fmt.Fprintf(os.Stderr, "\n")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var run func([]string) error
	switch strings.ToLower(os.Args[1]) {
	case "serve":
		run = runServe
	case "version":
		run = runVersion
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(1)
	}

	if err := run(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
`

const serverMakefileTemplate = `all: build

.PHONY: build

ifndef ($(GOPATH))
	GOPATH = $(HOME)/go
endif

PATH := $(GOPATH)/bin:$(PATH)
VERSION = $(shell git describe --tags --always --dirty)
BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
REVISION = $(shell git rev-parse HEAD)
REVSHORT = $(shell git rev-parse --short HEAD)
USER = $(shell whoami)
GOVERSION = $(shell go version | awk '{print $$3}')
NOW	= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
SHELL = /bin/bash

ifneq ($(OS), Windows_NT)
	CURRENT_PLATFORM = linux
	ifeq ($(shell uname), Darwin)
		SHELL := /bin/bash
		CURRENT_PLATFORM = darwin
	endif
else
	CURRENT_PLATFORM = windows
endif

BUILD_VERSION = "\
	-X github.com/micromdm/{{.Name}}/vendor/github.com/micromdm/go4/version.appName=${APP_NAME} \
	-X github.com/micromdm/{{.Name}}/vendor/github.com/micromdm/go4/version.version=${VERSION} \
	-X github.com/micromdm/{{.Name}}/vendor/github.com/micromdm/go4/version.branch=${BRANCH} \
	-X github.com/micromdm/{{.Name}}/vendor/github.com/micromdm/go4/version.buildUser=${USER} \
	-X github.com/micromdm/{{.Name}}/vendor/github.com/micromdm/go4/version.buildDate=${NOW} \
	-X github.com/micromdm/{{.Name}}/vendor/github.com/micromdm/go4/version.revision=${REVISION} \
	-X github.com/micromdm/{{.Name}}/vendor/github.com/micromdm/go4/version.goVersion=${GOVERSION}"

WORKSPACE = ${GOPATH}/src/github.com/micromdm/{{.Name}}
check-deps:
ifneq ($(shell test -e ${WORKSPACE}/Gopkg.lock && echo -n yes), yes)
	@echo "folder is clonded in the wrong place, copying to a Go Workspace"
	@echo "See: https://golang.org/doc/code.html#Workspaces"
	@git clone git@github.com:micromdm/{{.Name}} ${WORKSPACE}
	@echo "cd to ${WORKSPACE} and run make deps again."
	@exit 1
endif
ifneq ($(shell pwd), $(WORKSPACE))
	@echo "cd to ${WORKSPACE} and run make deps again."
	@exit 1
endif

deps: check-deps
	go get -u github.com/golang/dep/...
	dep ensure -vendor-only

test:
	go test -cover -race -v $(shell go list ./... | grep -v /vendor/)

build: {{.Name}}

clean:
	rm -rf build/
	rm -f *.zip

.pre-build:
	mkdir -p build/darwin
	mkdir -p build/linux

INSTALL_STEPS := \
	install-{{.Name}} 

install-local: $(INSTALL_STEPS)

.pre-{{.Name}}:
	$(eval APP_NAME = {{.Name}})

{{.Name}}: .pre-build .pre-{{.Name}}
	go build -i -o build/$(CURRENT_PLATFORM)/{{.Name}} -ldflags ${BUILD_VERSION} ./cmd/{{.Name}}

install-{{.Name}}: .pre-{{.Name}}
	go install -ldflags ${BUILD_VERSION} ./cmd/{{.Name}}

xp-{{.Name}}: .pre-build .pre-{{.Name}}
	GOOS=darwin go build -i -o build/darwin/{{.Name}} -ldflags ${BUILD_VERSION} ./cmd/{{.Name}}
	GOOS=linux CGO_ENABLED=0 go build -i -o build/linux/{{.Name}}  -ldflags ${BUILD_VERSION} ./cmd/{{.Name}}

release-zip: xp-{{.Name}}
	zip -r {{.Name}}_${VERSION}.zip build/

# TODO remove after bootstrap is done.
git-init:
	git init
	git add -A
	git commit -m "first commit."

dep-init:
	dep init
	git add Gopkg.*
	git commit -m "Initialize Go dependencies."

init: git-init dep-init
`

const serverServeTemplate = `
package main

import (
	"flag"
	stdlog "log"
	"net/http"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/groob/finalizer/logutil"
	"github.com/micromdm/go4/env"
	"github.com/micromdm/go4/httputil"
	"github.com/pkg/errors"
)

func runServe(args []string) error {
	flagset := flag.NewFlagSet("{{.Name}}", flag.ExitOnError)
	var (
		flConfigPath = flagset.String("config-dir", env.String("CONFIG_DIR", "/var/micromdm/{{.Name}}"), "Path to server config directory.")
		flLogFormat  = flagset.String("log-format", env.String("LOG_FORMAT", "logfmt"), "Enable structured logging. Supported formats: logfmt, json.")
		flLogLevel   = flagset.String("log-level", env.String("LOG_LEVEL", "info"), "Log level. Either info or debug.")
		flHTTPDebug  = flagset.Bool("http-debug", false, "Enable debug for http(dumps full request).")
		flHTTPAddr   = flagset.String("http-addr", env.String("HTTP_ADDR", ":https"), "HTTP(s) listen address of http server. Defaults to :443 or :8080 if tls=false")
		flTLS        = flagset.Bool("tls", env.Bool("USE_TLS", true), "Serve HTTPS.")
		flTLSCert    = flagset.String("tls-cert", env.String("TLS_CERT", ""), "Path to TLS certificate.")
		flTLSKey     = flagset.String("tls-key", env.String("TLS_KEY", ""), "Path to TLS private key.")
		flTLSDomain  = flagset.String("tls-domain", env.String("TLS_DOMAIN", ""), "Automatically fetch certs from Let's Encrypt for this domain. Format must be server.acme.co")
	)

	flagset.Usage = usageFor(flagset, "{{.Name}} serve [flags]")
	if err := flagset.Parse(args); err != nil {
		return err
	}

	var (
		logger     log.Logger
		httpLogger log.Logger
	)
	{
		w := log.NewSyncWriter(os.Stderr)
		switch *flLogFormat {
		case "json":
			logger = log.NewJSONLogger(w)
		default:
			logger = log.NewLogfmtLogger(w)
		}
		stdlog.SetOutput(log.NewStdlibAdapter(logger))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		if *flLogLevel == "debug" {
			logger = level.NewFilter(logger, level.AllowDebug())
		} else {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
		httpLogger = log.With(logger, "component", "http_logger")
		logger = log.With(logger, "caller", log.Caller(4))
	}

	mux := http.NewServeMux()
	var handler http.Handler
	if *flHTTPDebug {
		handler = httputil.HTTPDebugMiddleware(os.Stdout, true, httpLogger.Log)(mux)
	} else {
		handler = mux
	}
	handler = logutil.NewHTTPLogger(httpLogger).Middleware(handler)

	serveOpts := httputil.Simple(
		*flConfigPath,
		handler,
		*flHTTPAddr,
		*flTLSCert,
		*flTLSKey,
		*flTLS,
		logger,
		*flTLSDomain,
	)

	err := httputil.ListenAndServe(serveOpts...)
	return errors.Wrap(err, "calling ListenAndServe")
}
`

const gitignoreTemplate = `.DS_Store
build/
vendor/
*.zip
*.tar.gz
`

const dockerfileTemplate = `FROM alpine

RUN apk --update add \
    ca-certificates

COPY ./build/linux/{{.Name}} /usr/bin/{{.Name}}

CMD ["{{.Name}}"]
`
