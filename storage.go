package niso

import "context"

// Storage is a backend used to persist data generated by the OAuth2 server
type Storage interface {
	// Close the resources the Storage potentially holds. (Implements io.Closer)
	Close() error

	// GetClientData fetches the data for a ClientData by id
	// Should return NotFoundError, so an E_INVALID_CLIENT error will be returned instead of E_SERVER_ERROR
	GetClientData(ctx context.Context, id string) (*ClientData, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorizeData(ctx context.Context, data *AuthorizeData) error

	// GetAuthorizeData looks up AuthorizeData by a code.
	//// ClientData information MUST be loaded together.
	// Optionally can return error if expired.
	GetAuthorizeData(ctx context.Context, code string) (*AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	DeleteAuthorizeData(ctx context.Context, code string) error

	// SaveAccess writes AccessData to storage.
	SaveAccessData(ctx context.Context, data *AccessData) error

	// GetRefreshTokenData retrieves refresh token data from the token string.
	GetRefreshTokenData(ctx context.Context, token string) (*RefreshTokenData, error)

	// SaveRefreshTokenData saves refresh token data so it can be retrieved with GetRefreshTokenData
	SaveRefreshTokenData(ctx context.Context, data *RefreshTokenData) error

	// DeleteRefreshTokenData revokes or deletes a RefreshToken.
	DeleteRefreshTokenData(ctx context.Context, token string) error
}

// NotFoundError can be used to differentiate between internal server errors and an entity not existing in storage.
type NotFoundError struct {
	Err error
}

func (e *NotFoundError) Error() string {
	return e.Err.Error()
}
