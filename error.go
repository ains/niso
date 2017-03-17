package niso

import "fmt"

// ErrorCode is an OAuth2 error code
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
	ErrorCode ErrorCode
	Err       error
}

// NewNisoError creates a new NisoError for a response error code and wraps the original error
func NewNisoError(code ErrorCode, error error) *NisoError {
	return &NisoError{
		ErrorCode: code,
		Err:       error,
	}
}

func (e *NisoError) Error() string {
	return fmt.Sprintf("(%s) %s", e.ErrorCode, e.Err.Error())
}
