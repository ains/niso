package niso

type ClientData struct {
	ClientId     string // Unique identifier for this client (https://tools.ietf.org/html/rfc6749#section-2.2)
	ClientSecret string // OAuth2 client secret (https://tools.ietf.org/html/rfc6749#section-2.3.1)
	RedirectUri  string // OAuth2 redirect URI
}

func (c *ClientData) ValidSecret(secret string) bool {
	// Consider doing constant time equality check
	return secret == c.ClientSecret
}
