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
	EInvalidRequest          ErrorCode = "invalid_request"
	EUnauthorizedClient      ErrorCode = "unauthorized_client"
	EAccessDenied            ErrorCode = "access_denied"
	EUnsupportedResponseType ErrorCode = "unsupported_response_type"
	EInvalidScope            ErrorCode = "invalid_scope"
	EServerError             ErrorCode = "server_error"
	ETemporarilyUnavailable  ErrorCode = "temporarily_unavailable"
	EUnsupportedGrantType    ErrorCode = "unsupported_grant_type"
	EInvalidGrant            ErrorCode = "invalid_grant"
	EInvalidClient           ErrorCode = "invalid_client"
)

var defaultErrorMessages = map[ErrorCode]string{
	EInvalidRequest:          "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	EUnauthorizedClient:      "The client is not authorized to request a token using this method.",
	EAccessDenied:            "The resource owner or authorization server denied the request.",
	EUnsupportedResponseType: "The authorization server does not support obtaining a token using this method.",
	EInvalidScope:            "The requested scope is invalid, unknown, or malformed.",
	EServerError:             "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
	ETemporarilyUnavailable:  "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
	EUnsupportedGrantType:    "The authorization grant type is not supported by the authorization server.",
	EInvalidGrant:            "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	EInvalidClient:           "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
}

// Error is a wrapper around an existing error with an OAuth2 error code
type Error struct {
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

// NewError creates a new Error for a response error code
func NewError(code ErrorCode, message string, args ...interface{}) *Error {
	return &Error{
		Code:    code,
		Err:     errors.Errorf(message, args...),
		Message: message,
	}
}

// NewWrappedError creates a new Error for a response error code and wraps the original error with the given description
func NewWrappedError(code ErrorCode, error error, message string, args ...interface{}) *Error {
	return &Error{
		Code:    code,
		Err:     errors.Wrapf(error, message, args...),
		Message: message,
	}
}

// SetRedirectURI set redirect uri for this error to redirect to when written to a HTTP response
func (e *Error) SetRedirectURI(redirectURI string) {
	e.redirectURI = redirectURI
}

// SetState sets the "state" parameter to be returned to the user when this error is rendered
func (e *Error) SetState(state string) {
	e.state = state
}

func (e *Error) Error() string {
	errorMessage := e.Err.Error()
	if errorMessage == "" {
		return fmt.Sprintf("(%s)", e.Code)
	}
	return fmt.Sprintf("(%s) %s", e.Code, errorMessage)
}

// AsResponse creates a response object from this error, containing it's body or a redirect if specified
func (e *Error) AsResponse() *Response {
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
func (e *Error) GetRedirectURI() (string, error) {
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
func (e *Error) GetResponseDict() map[string]string {
	desc := e.Message
	if defaultMessage, ok := defaultErrorMessages[e.Code]; desc == "" && ok {
		desc = defaultMessage
	}

	return map[string]string{
		"error":             string(e.Code),
		"error_description": desc,
		"state":             e.state,
	}
}

func toInternalError(err error) *Error {
	if ne, ok := err.(*Error); ok {
		return ne
	}

	return &Error{
		Code:    EServerError,
		Err:     err,
		Message: err.Error(),
	}
}

// status code to return for a given error code as per (https://tools.ietf.org/html/rfc6749#section-5.2)
func statusCodeForError(error *Error) int {
	if error.Code == EServerError {
		return 500
	} else if error.Code == ETemporarilyUnavailable {
		return 503
	} else if error.Code == EInvalidClient || error.Code == EAccessDenied {
		return 401
	}

	return 400
}
