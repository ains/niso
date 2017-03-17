package niso

import (
	"fmt"

	"net/url"

	"github.com/pkg/errors"
)

// Code is an OAuth2 error code
type ErrorCode string

// OAuth2 error codes (https://tools.ietf.org/html/rfc6749#section-4.1.2.1)
const (
	E_INVALID_REQUEST           ErrorCode = "invalid_request"
	E_UNAUTHORIZED_CLIENT                 = "unauthorized_client"
	E_ACCESS_DENIED                       = "access_denied"
	E_UNSUPPORTED_RESPONSE_TYPE           = "unsupported_response_type"
	E_INVALID_SCOPE                       = "invalid_scope"
	E_SERVER_ERROR                        = "server_error"
	E_TEMPORARILY_UNAVAILABLE             = "temporarily_unavailable"
	E_UNSUPPORTED_GRANT_TYPE              = "unsupported_grant_type"
	E_INVALID_GRANT                       = "invalid_grant"
	E_INVALID_CLIENT                      = "invalid_client"
)

// NisoError is a wrapper around an existing error with an OAuth2 error code
type NisoError struct {
	Code ErrorCode
	Err  error

	// Human readable description of the error that occurred
	Message string

	// redirectURI is the URI to which the request will be redirected to when using WriteErrorResponse
	// as per https://tools.ietf.org/html/rfc6749#section-4.2.2.1
	redirectURI string

	// State is the state parameter to be passed directly back to the client
	state string
}

// NewNisoError creates a new NisoError for a response error code
func NewNisoError(code ErrorCode, message string) *NisoError {
	return &NisoError{
		Code:    code,
		Err:     errors.New(message),
		Message: message,
	}
}

// NewWrappedNisoError creates a new NisoError for a response error code and wraps the original error with the given description
func NewWrappedNisoError(code ErrorCode, error error, message string) *NisoError {
	return &NisoError{
		Code:    code,
		Err:     errors.Wrap(error, message),
		Message: message,
	}
}

func (e *NisoError) SetRedirectUri(redirectUri string) {
	e.redirectURI = redirectUri
}

func (e *NisoError) SetState(state string) {
	e.state = state
}

func (e *NisoError) Error() string {
	return fmt.Sprintf("(%s) %s", e.Code, e.Err.Error())
}

func (e *NisoError) GetRedirectUri() (string, error) {
	if e.redirectURI == "" {
		return "", nil
	}

	u, err := url.Parse(e.redirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	for k, v := range e.GetResponseDict() {
		if v != "" {
			q.Set(k, v)
		}
	}

	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func (e *NisoError) GetResponseDict() map[string]string {
	return map[string]string{
		"error":             string(e.Code),
		"error_description": e.Message,
		"state":             e.state,
	}
}
