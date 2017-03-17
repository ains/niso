package niso

import (
	"context"

	"github.com/pkg/errors"
)

// ClientData is the information stored for an OAuth2 client
type ClientData struct {
	ClientID     string // Unique identifier for this client (https://tools.ietf.org/html/rfc6749#section-2.2)
	ClientSecret string // OAuth2 client secret (https://tools.ietf.org/html/rfc6749#section-2.3.1)
	RedirectURI  string // OAuth2 redirect URI
}

// ValidSecret checks if the given secret is valid for this OAuth2 client
func (c *ClientData) ValidSecret(secret string) bool {
	// Consider doing constant time equality check
	return secret == c.ClientSecret
}

// getClientDataFromBasicAuth looks up and authenticates the basic auth using the given storage.
func getClientDataFromBasicAuth(ctx context.Context, auth *BasicAuth, storage Storage) (*ClientData, error) {
	clientData, err := getClientData(ctx, auth.Username, storage)
	if err != nil {
		return nil, err
	}

	if !clientData.ValidSecret(auth.Password) {
		return nil, NewNisoError(E_UNAUTHORIZED_CLIENT, errors.New("invalid secret for client"))
	}

	return clientData, err
}

func getClientData(ctx context.Context, clientID string, storage Storage) (*ClientData, error) {
	clientData, err := storage.GetClientData(ctx, clientID)
	if err != nil {
		if _, ok := err.(*NotFoundError); ok {
			return nil, NewNisoError(E_UNAUTHORIZED_CLIENT, errors.Wrap(err, "could not find client"))
		}

		return nil, NewNisoError(E_SERVER_ERROR, errors.Wrap(err, "failed to get client data from storage"))
	}

	if clientData.RedirectURI == "" {
		return nil, NewNisoError(E_SERVER_ERROR, errors.New("client does not have a valid redirect uri set"))
	}

	return clientData, err
}
