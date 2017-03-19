package niso

import (
	"errors"
	"net/http"
)

// BasicAuth is the parsed basic authentication header
type BasicAuth struct {
	Username string
	Password string
}

// getClientAuthFromRequest checks client basic authentication in params if allowed,
// otherwise gets it from the header.
// Sets an error on the response if no auth is present or a server error occurs.
func getClientAuthFromRequest(r *http.Request, allowQueryParams bool) (*BasicAuth, error) {
	if allowQueryParams {
		// Allow for auth without password
		auth := &BasicAuth{
			Username: r.FormValue("client_id"),
			Password: r.FormValue("client_secret"),
		}
		if auth.Username != "" {
			return auth, nil
		}
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, errors.New("Invalid authorization header")
	}

	return &BasicAuth{
		Username: user,
		Password: pass,
	}, nil
}
