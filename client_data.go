package niso

import "context"

// ClientData is the information stored for an OAuth2 client
type ClientData struct {
	ClientID     string // Unique identifier for this client (https://tools.ietf.org/html/rfc6749#section-2.2)
	ClientSecret string // OAuth2 client secret (https://tools.ietf.org/html/rfc6749#section-2.3.1)
	RedirectURI  string // OAuth2 redirect URI

	Labels map[string]string
}

// ValidSecret checks if the given secret is valid for this OAuth2 client
func (c *ClientData) ValidSecret(secret string) bool {
	// Consider doing constant time equality check
	return secret == c.ClientSecret
}

// getClientDataAndValidate looks up and authenticates the basic auth using the given storage.
func getClientDataAndValidate(ctx context.Context, auth *BasicAuth, storage Storage) (*ClientData, error) {
	clientData, err := getClientData(ctx, auth.Username, storage)
	if err != nil {
		return nil, err
	}

	if !clientData.ValidSecret(auth.Password) {
		return nil, NewError(EUnauthorizedClient, "invalid secret for client")
	}

	return clientData, nil
}

func getClientData(ctx context.Context, clientID string, storage Storage) (*ClientData, error) {
	clientData, err := storage.GetClientData(ctx, clientID)
	if err != nil {
		if _, ok := err.(*NotFoundError); ok {
			return nil, NewWrappedError(EUnauthorizedClient, err, "could not find client")
		}

		return nil, NewWrappedError(EServerError, err, "failed to get client data from storage")
	}

	if clientData.RedirectURI == "" {
		return nil, NewError(EServerError, "client does not have a valid redirect uri set")
	}

	return clientData, nil
}
