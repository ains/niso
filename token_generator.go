package niso

import (
	"encoding/base64"

	"github.com/pborman/uuid"
)

// DefaultAuthorizeTokenGenerator is the default authorization token generator
type DefaultAuthorizeTokenGenerator struct {
}

// GenerateAuthorizeToken generates a base64-encoded UUID code
func (a *DefaultAuthorizeTokenGenerator) GenerateAuthorizeToken(data *AuthorizationRequest) (string, error) {
	token := uuid.NewRandom()
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil
}

// DefaultAccessTokenGenerator is the default authorization token generator
type DefaultAccessTokenGenerator struct {
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *DefaultAccessTokenGenerator) GenerateAccessToken(ar *AccessRequest) (string, error) {
	token := uuid.NewRandom()
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *DefaultAccessTokenGenerator) GenerateRefreshToken(ar *AccessRequest) (string, error) {
	token := uuid.NewRandom()
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil
}
