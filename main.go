package tlsauth

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// Config is the plugin configuration.
type Config struct {
	Users          map[string]string
	UsernameHeader string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// TLSAuth is a TLS authentication plugin.
type TLSAuth struct {
	next   http.Handler
	name   string
	config *Config
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Log the instantiation of the plugin, including configuration.
	fmt.Fprintf(os.Stdout, "creating tlsauth plugin %q with config: %+v\n", name, config)

	// Return new plugin instance.
	return &TLSAuth{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

// ServeHTTP handles a http request.
func (ta *TLSAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if we have a client certificate.
	switch {
	case r.TLS == nil:
		http.Error(w, "TLS encryption is required for TLS based client authentication. (tlsauth)", http.StatusBadRequest)
		return
	case len(r.TLS.PeerCertificates) == 0:
		http.Error(w, "TLS client certificate is required for TLS based client authentication. (tlsauth)", http.StatusBadRequest)
		return
	}

	// Find a user with the certificate.
	username, ok := ta.findUserByCert(r.TLS.PeerCertificates[0])
	if !ok {
		// Respond with error when no user could be found.
		http.Error(w, "TLS client certificate not permitted. (tlsauth)", http.StatusForbidden)
		return
	}

	// Set username in header, if configured.
	if ta.config.UsernameHeader != "" {
		r.Header.Set(ta.config.UsernameHeader, username)
	}

	// Continue with next handler.
	ta.next.ServeHTTP(w, r)
}

func (ta *TLSAuth) findUserByCert(cert *x509.Certificate) (username string, ok bool) {
	// Check Common Name.
	username, ok = ta.findUserByID(cert.Subject.CommonName)
	if ok {
		return username, true
	}

	// Check DNS names.
	for _, dnsName := range cert.DNSNames {
		username, ok = ta.findUserByID(dnsName)
		if ok {
			return username, true
		}
	}

	// Check email addresses.
	for _, email := range cert.EmailAddresses {
		username, ok = ta.findUserByID(email)
		if ok {
			return username, true
		}
	}

	return "", false
}

func (ta *TLSAuth) findUserByID(userID string) (username string, ok bool) {
	// Check if name is empty.
	if userID == "" {
		return "", false
	}

	// Check if user is in users config.
	username, ok = ta.config.Users[userID]
	if !ok {
		return "", false
	}

	// Fallback to user ID if username is empty.
	if username == "" {
		username = userID
	}

	return username, true
}
