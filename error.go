package niso

import (
	"fmt"

	"net/url"

	"github.com/pkg/errors"
)

// ErrorCode is an OAuth2 error code
type ErrorCode string

// OAuth2 error codes (https://tools.ietf.org/html/rfc6749#section-4.1.2.1)
const (
	E_INVALID_REQUEST           ErrorCode = "invalid_request"
	E_UNAUTHORIZED_CLIENT       ErrorCode = "unauthorized_client"
	E_ACCESS_DENIED             ErrorCode = "access_denied"
	E_UNSUPPORTED_RESPONSE_TYPE ErrorCode = "unsupported_response_type"
	E_INVALID_SCOPE             ErrorCode = "invalid_scope"
	E_SERVER_ERROR              ErrorCode = "server_error"
	E_TEMPORARILY_UNAVAILABLE   ErrorCode = "temporarily_unavailable"
	E_UNSUPPORTED_GRANT_TYPE    ErrorCode = "unsupported_grant_type"
	E_INVALID_GRANT             ErrorCode = "invalid_grant"
	E_INVALID_CLIENT            ErrorCode = "invalid_client"
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
func NewNisoError(code ErrorCode, message string, args ...interface{}) *NisoError {
	return &NisoError{
		Code:    code,
		Err:     errors.Errorf(message, args...),
		Message: message,
	}
}

// NewWrappedNisoError creates a new NisoError for a response error code and wraps the original error with the given description
func NewWrappedNisoError(code ErrorCode, error error, message string, args ...interface{}) *NisoError {
	return &NisoError{
		Code:    code,
		Err:     errors.Wrapf(error, message, args...),
		Message: message,
	}
}

// SetRedirectURI set redirect uri for this error to redirect to when written to a HTTP response
func (e *NisoError) SetRedirectURI(redirectURI string) {
	e.redirectURI = redirectURI
}

// SetState sets the "state" parameter to be returned to the user when this error is rendered
func (e *NisoError) SetState(state string) {
	e.state = state
}

func (e *NisoError) Error() string {
	return fmt.Sprintf("(%s) %s", e.Code, e.Err.Error())
}

// AsResponse creates a response object from this error, containing it's body or a redirect if specified
func (e *NisoError) AsResponse() *Response {
	resp := NewResponse()

	// Redirect user if needed
	loc, err := e.GetRedirectURI()
	if err != nil {
		return newInternalServerErrorResponse(
			errors.Wrap(err, "failed to redirect on error").Error(),
		)
	}
	if loc != "" {
		resp.responseType = REDIRECT
		resp.redirectURL = loc
	}

	// No redirect output error as a JSON response
	resp.StatusCode = statusCodeForError(e)
	for k, v := range e.GetResponseDict() {
		if v != "" {
			resp.Data[k] = v
		}
	}

	return resp
}

// GetRedirectURI returns location to redirect user to after processing this error, or empty string if there is none
func (e *NisoError) GetRedirectURI() (string, error) {
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

// GetResponseDict returns the fields for an error response as defined in https://tools.ietf.org/html/rfc6749#section-4.2.2.1
func (e *NisoError) GetResponseDict() map[string]string {
	return map[string]string{
		"error":             string(e.Code),
		"error_description": e.Message,
		"state":             e.state,
	}
}

func toNisoError(err error) *NisoError {
	if ne, ok := err.(*NisoError); ok {
		return ne
	}

	return &NisoError{
		Code:    E_SERVER_ERROR,
		Err:     err,
		Message: err.Error(),
	}
}

// status code to return for a given error code as per (https://tools.ietf.org/html/rfc6749#section-5.2)
func statusCodeForError(error *NisoError) int {
	if error.Code == E_SERVER_ERROR {
		return 500
	} else if error.Code == E_TEMPORARILY_UNAVAILABLE {
		return 503
	} else if error.Code == E_INVALID_CLIENT || error.Code == E_ACCESS_DENIED {
		return 401
	}

	return 400
}
