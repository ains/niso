package niso

import (
	"context"
	"net/http"
	"regexp"
	"time"
)

// AuthorizeResponseType is the type for OAuth param `response_type`
type AuthorizeResponseType string

// AuthorizeResponseType is either code or token
const (
	CODE  AuthorizeResponseType = "code"
	TOKEN AuthorizeResponseType = "token"
)

// PKCECodeChallengeMethod is the code_challenge field as described in rfc7636
type PKCECodeChallengeMethod string

// https://tools.ietf.org/html/rfc7636#section-4.2
const (
	PKCE_PLAIN PKCECodeChallengeMethod = "plain"
	PKCE_S256  PKCECodeChallengeMethod = "S256"
)

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
)

// AuthRequestAuthorizedCallback returns if an authorization request should succeed or access should be denied.
// errors returned by this function will result in internal server errors being returned
type AuthRequestAuthorizedCallback func(ar *AuthorizationRequest) (bool, error)

// AuthorizationRequest represents an incoming authorization request
type AuthorizationRequest struct {
	ResponseType AuthorizeResponseType
	ClientID     string
	Scope        string
	RedirectURI  string
	State        string

	// Token expiration in seconds. Change if different from default.
	// If type = TOKEN, this expiration will be for the ACCESS token.
	Expiration int32

	// Optional code_challenge as described in rfc7636
	CodeChallenge string
	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod PKCECodeChallengeMethod

	// (optional) Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// AuthorizeData represents an issued authorization code
type AuthorizeData struct {
	// ClientData information
	ClientID string

	// Authorization code
	Code string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectURI string

	// State data from request
	State string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// Optional code_challenge as described in rfc7636
	CodeChallenge string
	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod PKCECodeChallengeMethod
}

// IsExpiredAt is true if authorization has expired by time 't'
func (d *AuthorizeData) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *AuthorizeData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AuthorizeTokenGenerator is the token generator interface
type AuthorizeTokenGenerator interface {
	GenerateAuthorizeToken(data *AuthorizationRequest) (string, error)
}

// GenerateAuthorizationRequest handles authorization requests. Generates an AuthorizationRequest from a HTTP request.
func (s *Server) GenerateAuthorizationRequest(ctx context.Context, r *http.Request) (*AuthorizationRequest, error) {
	clientID := r.FormValue("client_id")

	// must have a valid client
	clientData, err := getClientData(ctx, clientID, s.Storage)
	if err != nil {
		return nil, err
	}

	// if there are multiple client redirect uri's don't set the uri
	redirectURI := r.FormValue("redirect_uri")
	clientRedirectURI := clientData.RedirectURI
	URISeparator := s.Config.RedirectURISeparator
	if redirectURI == "" && firstURI(clientRedirectURI, URISeparator) == clientRedirectURI {
		redirectURI = firstURI(clientRedirectURI, URISeparator)
	}

	ar := &AuthorizationRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               r.FormValue("state"),
		Scope:               r.FormValue("scope"),
		ResponseType:        AuthorizeResponseType(r.FormValue("response_type")),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: PKCECodeChallengeMethod(r.FormValue("code_challenge_method")),
	}

	if err := s.validateAuthorizationRequest(ctx, ar); err != nil {
		return nil, err
	}

	return ar, nil
}

func (s *Server) validateAuthorizationRequest(ctx context.Context, ar *AuthorizationRequest) error {
	// Validate redirect uri - invalid redirect URI's do not produce redirecting errors.
	reqRedirectURI := ar.RedirectURI
	// must have a valid client
	clientData, err := getClientData(ctx, ar.ClientID, s.Storage)
	if err != nil {
		return err
	}

	// check redirect uri, if there are multiple client redirect uri's don't set the uri
	clientRedirectURI := clientData.RedirectURI
	URISeparator := s.Config.RedirectURISeparator
	if reqRedirectURI == "" && firstURI(clientRedirectURI, URISeparator) == clientRedirectURI {
		reqRedirectURI = firstURI(clientRedirectURI, URISeparator)
	}
	if err = validateURIList(clientRedirectURI, reqRedirectURI, URISeparator); err != nil {
		return NewWrappedNisoError(E_INVALID_REQUEST, err, "specified redirect_uri not valid for the given client_id")
	}

	// Redirect uri is valid, all future errors will redirect to redirectURI
	if s.Config.AllowedAuthorizeTypes.Exists(ar.ResponseType) {
		ar.Expiration = s.Config.AuthorizationExpiration

		if ar.ResponseType == CODE {
			// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
			if codeChallenge := ar.CodeChallenge; len(codeChallenge) == 0 {
				if s.Config.RequirePKCEForPublicClients && clientData.ClientSecret == "" {
					// https://tools.ietf.org/html/rfc7636#section-4.4.1
					return errorWithRedirect(ar, NewNisoError(E_INVALID_REQUEST, "code_challenge (rfc7636) required for public clients"))
				}
			} else {
				codeChallengeMethod := ar.CodeChallengeMethod
				// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
				if len(codeChallengeMethod) == 0 {
					codeChallengeMethod = PKCE_PLAIN
				}
				if codeChallengeMethod != PKCE_PLAIN && codeChallengeMethod != PKCE_S256 {
					// https://tools.ietf.org/html/rfc7636#section-4.4.1
					return errorWithRedirect(ar, NewNisoError(E_INVALID_REQUEST, "code_challenge_method transform algorithm not supported (rfc7636)"))
				}

				// https://tools.ietf.org/html/rfc7636#section-4.2
				if matched := pkceMatcher.MatchString(codeChallenge); !matched {
					return errorWithRedirect(ar, NewNisoError(E_INVALID_REQUEST, "code_challenge invalid (rfc7636)"))
				}

				ar.CodeChallenge = codeChallenge
				ar.CodeChallengeMethod = codeChallengeMethod
			}
		}

		return nil
	}

	return errorWithRedirect(ar, NewNisoError(E_UNSUPPORTED_RESPONSE_TYPE, "request type not in server allowed authorize types"))

}

// errors caused by invalid client identifiers or redirect URIs will not cause redirects
// if an error occurs post redirect uri validation, redirect with error in query
// (https://tools.ietf.org/html/rfc6749#section-4.1.2.1)
func errorWithRedirect(ar *AuthorizationRequest, err error) error {
	nisoErr := toNisoError(err)

	nisoErr.SetRedirectURI(ar.RedirectURI)
	nisoErr.SetState(ar.State)

	return nisoErr
}

// HandleHTTPAuthorizeRequest is the main entry point for handling authorization requests.
// This method will always return a Response, even if there was an error processing the request, which should be
// rendered for a user. It may also return an error in the second argument which can be logged by the caller.
func (s *Server) HandleHTTPAuthorizeRequest(ctx context.Context, r *http.Request, isAuthorizedCb AuthRequestAuthorizedCallback) (*Response, error) {
	ar, err := s.GenerateAuthorizationRequest(ctx, r)
	if err != nil {
		return toNisoError(err).AsResponse(), err
	}

	isAuthorized, err := isAuthorizedCb(ar)
	if err != nil {
		err = errorWithRedirect(ar, NewWrappedNisoError(E_SERVER_ERROR, err, "authorization check failed"))
		return toNisoError(err).AsResponse(), err
	}

	if !isAuthorized {
		err = errorWithRedirect(ar, NewNisoError(E_ACCESS_DENIED, "access denied"))
		return toNisoError(err).AsResponse(), err
	}

	resp, err := s.FinishAuthorizeRequest(ctx, ar)
	if err != nil {
		return toNisoError(err).AsResponse(), err
	}

	return resp, nil
}

// FinishAuthorizeRequest takes in a authorization request and returns a response to the client or an error
func (s *Server) FinishAuthorizeRequest(ctx context.Context, ar *AuthorizationRequest) (*Response, error) {
	resp, err := s.finishAuthorizeRequest(ctx, ar)
	if err != nil {
		return nil, errorWithRedirect(ar, err)
	}

	return resp, nil
}

func (s *Server) finishAuthorizeRequest(ctx context.Context, ar *AuthorizationRequest) (*Response, error) {
	if ar.ResponseType == TOKEN {
		// generate token directly
		ret := &AccessRequest{
			GrantType:       IMPLICIT,
			Code:            "",
			ClientID:        ar.ClientID,
			RedirectURI:     ar.RedirectURI,
			Scope:           ar.Scope,
			GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
			Expiration:      ar.Expiration,
			UserData:        ar.UserData,
		}

		resp, err := s.FinishAccessRequest(ctx, ret)
		if err != nil {
			return nil, err
		}

		resp.SetRedirectURL(ar.RedirectURI)
		resp.SetRedirectFragment(true)
		if ar.State != "" {
			resp.Data["state"] = ar.State
		}
		return resp, nil
	}

	resp := NewResponse()
	resp.SetRedirectURL(ar.RedirectURI)

	// generate authorization token
	ret := &AuthorizeData{
		ClientID:    ar.ClientID,
		CreatedAt:   s.Now(),
		ExpiresIn:   ar.Expiration,
		RedirectURI: ar.RedirectURI,
		State:       ar.State,
		Scope:       ar.Scope,
		UserData:    ar.UserData,
		// Optional PKCE challenge
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
	}

	// generate token code
	code, err := s.AuthorizeTokenGenerator.GenerateAuthorizeToken(ar)
	if err != nil {
		return nil, NewWrappedNisoError(E_SERVER_ERROR, err, "failed to generate authorize token")

	}
	ret.Code = code

	// save authorization token
	if err = s.Storage.SaveAuthorizeData(ctx, ret); err != nil {
		return nil, NewWrappedNisoError(E_SERVER_ERROR, err, "failed to save authorize data")
	}

	// redirect with code
	resp.Data["code"] = ret.Code
	resp.Data["state"] = ret.State
	return resp, nil
}
