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
// Sets an error on the response if no auth is present, and query params are not accepted.
func getClientAuthFromRequest(r *http.Request, allowQueryParams bool) (*BasicAuth, error) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		if allowQueryParams {
			user = r.FormValue("client_id")
			pass = r.FormValue("client_secret")
		} else {
			return nil, errors.New("invalid authorization header")
		}
	}

	return &BasicAuth{
		Username: user,
		Password: pass,
	}, nil
}
