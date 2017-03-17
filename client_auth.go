package niso

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// BasicAuth is the parsed basic authentication header
type BasicAuth struct {
	Username string
	Password string
}

// Return authorization header data
func parseBasicAuth(r *http.Request) (*BasicAuth, error) {
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return nil, errors.New("Invalid authorization header")
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return nil, errors.New("Invalid authorization message")
	}

	return &BasicAuth{Username: pair[0], Password: pair[1]}, nil
}

// getClientAuthFromRequest checks client basic authentication in params if allowed,
// otherwise gets it from the header.
// Sets an error on the response if no auth is present or a server error occurs.
func getClientAuthFromRequest(r *http.Request, allowQueryParams bool) (*BasicAuth, error) {
	if allowQueryParams {
		// Allow for auth without password
		if _, hasSecret := r.Form["client_secret"]; hasSecret {
			auth := &BasicAuth{
				Username: r.Form.Get("client_id"),
				Password: r.Form.Get("client_secret"),
			}
			if auth.Username != "" {
				return auth, nil
			}
		}
	}

	auth, err := parseBasicAuth(r)
	if err != nil {
		return nil, err
	}

	if auth == nil {
		return nil, errors.New("Client authentication not sent")
	}

	return auth, nil
}
