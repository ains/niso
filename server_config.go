package niso

// AllowedAuthorizeTypes is a collection of allowed auth request types
type AllowedAuthorizeTypes []AuthorizeResponseType

// Exists returns true if the auth type exists in the list
func (t AllowedAuthorizeTypes) Exists(rt AuthorizeResponseType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

// AllowedAccessTypes is a collection of allowed access request types
type AllowedAccessTypes []GrantType

// Exists returns true if the access type exists in the list
func (t AllowedAccessTypes) Exists(rt GrantType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

// ServerConfig contains server configuration information
type ServerConfig struct {
	// Authorization token expiration in seconds (default 5 minutes)
	AuthorizationExpiration int32

	// Access token expiration in seconds (default 1 hour)
	AccessExpiration int32

	// Token type to return
	TokenType string

	// List of allowed authorize types (only ResponseTypeCode by default)
	AllowedAuthorizeTypes AllowedAuthorizeTypes

	// List of allowed access types (only GrantTypeAuthorizationCode by default)
	AllowedAccessTypes AllowedAccessTypes

	// If true allows client secret also in params, else only in
	// Authorization header - default false
	AllowClientSecretInParams bool

	// Require PKCE for code flows for public OAuth clients - default false
	RequirePKCEForPublicClients bool

	// Separator to support multiple URIs in ClientData.GetRedirectURI().
	// If blank (the default), don't allow multiple URIs.
	RedirectURISeparator string

	// If true allows access request using GET, else only POST - default false
	AllowGetAccessRequest bool
}

// NewServerConfig returns a new ServerConfig with default configuration
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		AuthorizationExpiration:   250,
		AccessExpiration:          3600,
		TokenType:                 "Bearer",
		AllowedAuthorizeTypes:     AllowedAuthorizeTypes{ResponseTypeCode},
		AllowedAccessTypes:        AllowedAccessTypes{GrantTypeAuthorizationCode},
		AllowClientSecretInParams: false,
	}
}
