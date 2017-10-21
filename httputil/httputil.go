// Package httputil provides utilities for configuring an HTTPs server.
package httputil

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Option configures the ListenAndServe function.
type Option func(*serverConfig)

// WithACMEHosts configures a list of domains to whitelist for Let's Encrypt.
// If unspecified, the server will whitelist the first successful ServerName
// for which it is able to get a certificate.
func WithACMEHosts(hosts []string) Option {
	return func(c *serverConfig) { c.LetsEncryptHosts = hosts }
}

// WithCertCache configures a directory to store Let's Encrypt certificates.
func WithCertCache(dir string) Option {
	return func(c *serverConfig) { c.LetsEncryptCache = dir }
}

// WithAutocertCache configures a custom autocert.Cache for Let's Encrypt Certificates.
func WithAutocertCache(cache autocert.Cache) Option {
	return func(c *serverConfig) { c.AutocertCache = cache }
}

// WithHTTPHandler configures the server to use a custom HTTP Handler.
// If unspecified, http.DefaultServeMux will be used.
func WithHTTPHandler(h http.Handler) Option {
	return func(c *serverConfig) { c.Handler = h }
}

// WithKeyPair configures a TLS certificate to be used in the server TLS Config.
func WithKeyPair(cert, key string) Option {
	return func(c *serverConfig) {
		c.TLSCertFile = cert
		c.TLSKeyFile = key
	}
}

// WithAddress configures the server listening port and address. If left unspecified,
// :https will be used by default.
func WithAddress(addr string) Option {
	return func(c *serverConfig) { c.Addr = addr }
}

// WithLogger provides a logger for ListenAndServe.
// Not to be confused with an HTTP Logging Middleware for the HTTP Handler itself.
func WithLogger(logger log.Logger) Option {
	return func(c *serverConfig) { c.logger = logger }
}

// WithMiddlewareChain chains Middleware for http.DefaultServeMux.
// If using WithHTTPHandler, the handler must already be wrapped with appropriate Middleware.
func WithMiddlewareChain(outer Middleware, others ...Middleware) Option {
	h := Chain(outer, others...)(http.DefaultServeMux)
	return WithHTTPHandler(h)
}

type serverConfig struct {
	// Addr specifies the host and port on which the server should listen.
	Addr string

	// AutocertCache provides a cache for use with Let's Encrypt.
	// If non-nil, enables Let's Encrypt certificates for this server.
	AutocertCache autocert.Cache

	// LetsEncryptCache specifies the cache file for Let's Encrypt.
	// If non-empty, enables Let's Encrypt certificates for this server.
	LetsEncryptCache string

	// LetsEncryptHosts specifies the list of hosts for which we should
	// obtain TLS certificates through Let's Encrypt. If LetsEncryptCache
	// is specified this should be specified also.
	LetsEncryptHosts []string

	// CertFile and KeyFile specifies the TLS certificates to use.
	// It has no effect if LetsEncryptCache is non-empty.
	TLSCertFile string
	TLSKeyFile  string

	// TLSConfig specifies an alternative TLSConfig to be used by the server.
	TLSConfig *tls.Config

	// Handler configures an HTTP handler for the server. If unspecified, http.DefaultServeMux is used.
	Handler http.Handler

	// Enforce a Strict Trasport Security (HSTS) Header for all HTTPS Connections.
	hsts bool

	logger log.Logger
}

func (cfg *serverConfig) apply(opts ...Option) {
	for _, opt := range opts {
		opt(cfg)
	}
}

// Simple returns a slice of ListenAndServe options that are most common for a
// micromdm server project's main.go
func Simple(
	configPath string, // folder where le-certificates will be created.
	handler http.Handler, // HTTP Handler to serve.
	httpAddr string, // serve address, default should be :https
	certPath, keyPath string, // tls credentials
	useTLS bool, // use :8080 if false
	logger log.Logger, // go-kit logger
	whitelistHosts ...string, // whitelist LE domains
) []Option {
	tlsFromFile := (certPath != "" && keyPath != "")
	serveOpts := []Option{
		WithACMEHosts(whitelistHosts),
		WithLogger(logger),
		WithHTTPHandler(handler),
	}
	if tlsFromFile {
		serveOpts = append(serveOpts, WithKeyPair(certPath, keyPath))
	}
	if !useTLS && httpAddr == ":https" {
		serveOpts = append(serveOpts, WithAddress(":8080"))
	}
	if useTLS {
		serveOpts = append(serveOpts, WithAutocertCache(autocert.DirCache(filepath.Join(configPath, "le-certificates"))))
	}
	if httpAddr != ":https" {
		serveOpts = append(serveOpts, WithAddress(httpAddr))
	}
	return serveOpts
}

// ListenAndServe starts an HTTP server and runs until it receives an Interrupt
// signal or an error.
//
// With a default config, the server will bind to port 443 and will try to use
// Let's Encrypt to manage the server certificate.
func ListenAndServe(opts ...Option) error {
	config := &serverConfig{
		Addr:    ":https",
		Handler: http.DefaultServeMux,
		hsts:    true,
		logger:  log.NewNopLogger(),
	}
	config.TLSConfig = &tls.Config{
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"},
	}
	setProfile(config.TLSConfig, modern)

	config.apply(opts...)

	if config.hsts {
		config.Handler = enforceHSTS()(config.Handler)
	}

	info := level.Info(config.logger)

	hasLetsEncryptCache := config.LetsEncryptCache != ""
	hasAutocertCache := config.AutocertCache != nil
	hasCert := config.TLSCertFile != "" || config.TLSKeyFile != ""

	var redirectHTTPS bool
	_, port, err := net.SplitHostPort(config.Addr)
	if err != nil {
		return errors.Wrapf(err, "httputil: couldn't parse address %q", config.Addr)
	}
	if port == "https" || port == "443" {
		redirectHTTPS = true
	}

	var m autocert.Manager
	m.Prompt = autocert.AcceptTOS
	if h := config.LetsEncryptHosts; len(h) > 0 {
		m.HostPolicy = autocert.HostWhitelist(h...)
	}

	shutdown := make(chan struct{})
	switch {
	case !hasCert && !hasAutocertCache && !hasLetsEncryptCache && config.Addr != ":https" && !redirectHTTPS:
		info.Log("msg", "serving insecure HTTP", "addr", config.Addr)
		config.TLSConfig = nil
	case hasLetsEncryptCache && !hasAutocertCache && !hasCert:
		dir := config.LetsEncryptCache
		info.Log("msg", "serving HTTPS using Let's Encrypt certificates", "addr", config.Addr, "cache", dir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return errors.Wrapf(err, "httputil: could not create or read letsencrypt cache directory %q", dir)
		}
		config.TLSConfig.GetCertificate = getCertificate(&m, config.LetsEncryptHosts, shutdown, config.logger)
		m.Cache = autocert.DirCache(dir)
	case hasAutocertCache && !hasCert:
		info.Log("msg", "serving HTTPS using Let's Encrypt certificates", "addr", config.Addr)
		config.TLSConfig.GetCertificate = getCertificate(&m, config.LetsEncryptHosts, shutdown, config.logger)
		m.Cache = config.AutocertCache
	case hasCert:
		info.Log("msg", "serving HTTPS using provided certificates", "addr", config.Addr)
		certfile, keyfile := config.TLSCertFile, config.TLSKeyFile
		cert, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			return errors.Wrap(err, "httputil: loading TLS certificate from file")
		}
		config.TLSConfig.Certificates = []tls.Certificate{cert}
		config.TLSConfig.BuildNameToCertificate()
	default:
		dir := filepath.Join(os.TempDir(), "letscache")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return errors.Wrapf(err, "httputil: could not create or read letsencrypt cache directory %q", dir)
		}
		info.Log("msg", "serving HTTPS using Let's Encrypt certificates", "addr", config.Addr, "cache", dir)
		config.TLSConfig.GetCertificate = getCertificate(&m, config.LetsEncryptHosts, shutdown, config.logger)
		m.Cache = autocert.DirCache(dir)
	}

	server := &http.Server{
		Handler:           config.Handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         config.TLSConfig,
	}

	errs := make(chan error)
	go func() {
		sig := make(chan os.Signal)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sig: // block on signal then gracefully shutdown.
		case <-shutdown:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		errs <- server.Shutdown(ctx)
	}()

	go func() {
		ln, err := net.Listen("tcp", config.Addr)
		if err != nil {
			errs <- errors.Wrap(err, "httputil: creating TCP Listener")
			return
		}
		if config.TLSConfig != nil {
			ln = tls.NewListener(ln, config.TLSConfig)
		}
		errs <- server.Serve(ln)
	}()

	if redirectHTTPS {
		go func() {
			errs <- (&http.Server{
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 5 * time.Second,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					w.Header().Set("Connection", "close")
					url := "https://" + req.Host + req.URL.String()
					http.Redirect(w, req, url, http.StatusMovedPermanently)
				}),
			}).ListenAndServe()
		}()
	}

	return <-errs
}

// tlsProfile represents a collection of TLS CipherSuites and their compatibility with Web Browsers.
// The different profile types are defined on the Mozilla wiki: https://wiki.mozilla.org/Security/Server_Side_TLS
type tlsProfile int

const (
	// Modern CipherSuites only.
	// This configuration is compatible with Firefox 27, Chrome 30, IE 11 on Windows 7,
	// Edge, Opera 17, Safari 9, Android 5.0, and Java 8.
	modern tlsProfile = iota

	// Intermediate supports a wider range of CipherSuites than Modern and
	// is compatible with Firefox 1, Chrome 1, IE 7, Opera 5 and Safari 1.
	intermediate

	// Old provides backwards compatibility for legacy clients.
	// Should only be used as a last resort.
	old
)

func (p tlsProfile) String() string {
	switch p {
	case modern:
		return "modern"
	case intermediate:
		return "intermediate"
	case old:
		return "old"
	default:
		panic("unknown TLS profile constant: " + fmt.Sprintf("%d", p))
	}
}

func setProfile(cfg *tls.Config, profile tlsProfile) {
	switch profile {
	case modern:
		cfg.MinVersion = tls.VersionTLS12
		cfg.CurvePreferences = append(cfg.CurvePreferences,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
			tls.X25519,
		)
		cfg.CipherSuites = append(cfg.CipherSuites,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		)
	case intermediate:
		cfg.MinVersion = tls.VersionTLS10
		cfg.CurvePreferences = append(cfg.CurvePreferences,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
			tls.X25519,
		)
		cfg.CipherSuites = append(cfg.CipherSuites,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		)
	case old:
		cfg.MinVersion = tls.VersionSSL30
		cfg.CurvePreferences = append(cfg.CurvePreferences,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
			tls.X25519,
		)
		cfg.CipherSuites = append(cfg.CipherSuites,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		)
	default:
		panic("invalid tls profile " + profile.String())
	}
}

func getCertificate(
	manager *autocert.Manager,
	whitelist []string,
	shutdown chan<- struct{},
	logger log.Logger,
) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := manager.GetCertificate(hello)
		if err != nil {
			if e, ok := err.(*acme.AuthorizationError); ok {
				level.Info(logger).Log("err", "acme authorization error", "identifier", e.Identifier, "uri", e.URI)
				if len(whitelist) == 1 {
					level.Info(logger).Log(
						"msg", "server shutting down due to a failed Let's Encrypt Authorization error.",
					)
					go func() { shutdown <- struct{}{} }()
				}
			}
		}

		if err == nil && len(whitelist) == 0 && !strings.HasSuffix(hello.ServerName, "acme.invalid") {
			level.Info(logger).Log("msg", "whitelisting servername for Let's encrypt", "domain", hello.ServerName)
			manager.HostPolicy = autocert.HostWhitelist(hello.ServerName)
			whitelist = append(whitelist, hello.ServerName)
		}

		return cert, err
	}
}
