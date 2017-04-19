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

// getClientAuthFromRequest checks client basic auth from header. As a fallback, if allowed, it checks for user and
// password from query params.
// Sets an error on the response if no auth is present or a server error occurs.
func getClientAuthFromRequest(r *http.Request, allowQueryParams bool) (*BasicAuth, error) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, errors.New("invalid authorization header")
	}

	if (user == "" || pass == "") && allowQueryParams {
		// Allow for auth without password
		auth := &BasicAuth{
			Username: r.FormValue("client_id"),
			Password: r.FormValue("client_secret"),
		}
		if auth.Username != "" {
			return auth, nil
		}
	}

	return &BasicAuth{
		Username: user,
		Password: pass,
	}, nil
}
