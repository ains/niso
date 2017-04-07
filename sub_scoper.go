package niso

import (
	"strings"
)

// AccessTokenSubScoper checks if the requested scopes of AT are a subset of already granted scopes.
type AccessTokenSubScoper interface {
	CheckSubScopes(accessTokenScopes string, refreshTokenScopes string) (string, error)
}

// DefaultAccessTokenSubScoper checks if the given scopes of AT request are a string subset of already granted scopes.
type DefaultAccessTokenSubScoper struct {
}

// CheckSubScopes checks the given access token scopes to see if they are granted by the refresh token's scope,
// and returns the resulting subset of scopes.
func (a *DefaultAccessTokenSubScoper) CheckSubScopes(accessTokenScopes string, refreshTokenScopes string) (string, error) {
	refreshScopesLists := strings.Split(refreshTokenScopes, ",")
	accessScopeLists := strings.Split(accessTokenScopes, ",")

	refreshMaps := make(map[string]int)

	for _, scope := range refreshScopesLists {
		if scope == "" {
			continue
		}
		refreshMaps[scope] = 1
	}

	for _, scope := range accessScopeLists {
		if scope == "" {
			continue
		}
		if _, ok := refreshMaps[scope]; !ok {
			return "", NewError(EInvalidScope, "scope %v is not in original grant", scope)
		}
	}
	return accessTokenScopes, nil
}
