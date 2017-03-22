package niso

import (
	"context"
	"net/http"
	"net/url"
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
	ClientData   *ClientData
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
	ClientData *ClientData

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

// GenerateAuthorizeRequest handles authorization requests. Generates an AuthorizationRequest from a HTTP request.
func (s *Server) GenerateAuthorizeRequest(ctx context.Context, r *http.Request) (*AuthorizationRequest, error) {
	reqRedirectURI, err := url.QueryUnescape(r.FormValue("redirect_uri"))
	if err != nil {
		return nil, NewWrappedNisoError(E_INVALID_REQUEST, err, "redirect_uri is not a valid url-encoded string")
	}

	// must have a valid client
	clientData, err := getClientData(ctx, r.FormValue("client_id"), s.Storage)
	if err != nil {
		return nil, err
	}

	// check redirect uri, if there are multiple client redirect uri's don't set the uri
	clientRedirectURI := clientData.RedirectURI
	URISeparator := s.Config.RedirectURISeparator
	if reqRedirectURI == "" && firstURI(clientRedirectURI, URISeparator) == clientRedirectURI {
		reqRedirectURI = firstURI(clientRedirectURI, URISeparator)
	}
	if err = validateURIList(clientRedirectURI, reqRedirectURI, URISeparator); err != nil {
		return nil, NewWrappedNisoError(E_INVALID_REQUEST, err, "specified redirect_uri not valid for the given client_id")
	}

	ar := &AuthorizationRequest{
		State:               r.FormValue("state"),
		Scope:               r.FormValue("scope"),
		ResponseType:        AuthorizeResponseType(r.FormValue("response_type")),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: PKCECodeChallengeMethod(r.FormValue("code_challenge_method")),
	}
	ar.ClientData = clientData
	ar.RedirectURI = reqRedirectURI

	ret, err := s.generateAuthorizeRequest(ctx, ar)
	if err != nil {
		return nil, errorWithRedirect(ar, err)
	}

	return ret, nil
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

// HandleAuthorizeRequest is the main entry point for handling authorization requests.
// This method will always return a Response, even if there was an error processing the request, which should be
// rendered for a user. It may also return an error in the second argument which can be logged by the caller.
func (s *Server) HandleAuthorizeRequest(ctx context.Context, r *http.Request, isAuthorizedCb AuthRequestAuthorizedCallback) (*Response, error) {
	ar, err := s.GenerateAuthorizeRequest(ctx, r)
	if err != nil {
		return toNisoError(err).AsResponse(), err
	}

	isAuthorized, err := isAuthorizedCb(ar)
	if err != nil {
		err = NewWrappedNisoError(E_SERVER_ERROR, err, "authorization check failed")
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

func (s *Server) generateAuthorizeRequest(ctx context.Context, ret *AuthorizationRequest) (*AuthorizationRequest, error) {
	if s.Config.AllowedAuthorizeTypes.Exists(ret.ResponseType) {
		ret.Expiration = s.Config.AuthorizationExpiration

		if ret.ResponseType == CODE {
			// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
			if codeChallenge := ret.CodeChallenge; len(codeChallenge) == 0 {
				if s.Config.RequirePKCEForPublicClients && ret.ClientData.ClientSecret == "" {
					// https://tools.ietf.org/html/rfc7636#section-4.4.1
					return nil, NewNisoError(E_INVALID_REQUEST, "code_challenge (rfc7636) required for public clients")
				}
			} else {
				codeChallengeMethod := ret.CodeChallengeMethod
				// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
				if len(codeChallengeMethod) == 0 {
					codeChallengeMethod = PKCE_PLAIN
				}
				if codeChallengeMethod != PKCE_PLAIN && codeChallengeMethod != PKCE_S256 {
					// https://tools.ietf.org/html/rfc7636#section-4.4.1
					return nil, NewNisoError(E_INVALID_REQUEST, "code_challenge_method transform algorithm not supported (rfc7636)")
				}

				// https://tools.ietf.org/html/rfc7636#section-4.2
				if matched := pkceMatcher.MatchString(codeChallenge); !matched {
					return nil, NewNisoError(E_INVALID_REQUEST, "code_challenge invalid (rfc7636)")
				}

				ret.CodeChallenge = codeChallenge
				ret.CodeChallengeMethod = codeChallengeMethod
			}
		}

		return ret, nil
	}

	return nil, NewNisoError(E_UNSUPPORTED_RESPONSE_TYPE, "request type not in server allowed authorize types")
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
			ClientData:      ar.ClientData,
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
		ClientData:  ar.ClientData,
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
		return nil, NewWrappedNisoError(E_SERVER_ERROR, err, "Failed to generate authorize token")

	}
	ret.Code = code

	// save authorization token
	if err = s.Storage.SaveAuthorizeData(ctx, ret); err != nil {
		return nil, NewWrappedNisoError(E_SERVER_ERROR, err, "Failed to save authorize data")
	}

	// redirect with code
	resp.Data["code"] = ret.Code
	resp.Data["state"] = ret.State
	return resp, nil
}
