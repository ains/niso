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
	ResponseTypeCode  AuthorizeResponseType = "code"
	ResponseTypeToken AuthorizeResponseType = "token"
)

// PKCECodeChallengeMethod is the code_challenge field as described in rfc7636
type PKCECodeChallengeMethod string

// https://tools.ietf.org/html/rfc7636#section-4.2
const (
	PKCEPlain PKCECodeChallengeMethod = "plain"
	PKCES256  PKCECodeChallengeMethod = "S256"
)

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
)

// AuthRequestAuthorizedCallback returns if an authorization request should succeed or access should be denied.
// errors returned by this function will result in internal server errors being returned
type AuthRequestAuthorizedCallback func(ar *AuthorizationRequest) (bool, error)

// AuthRequestGenerator generates and returns an AuthorizationRequest to process or an error.
type AuthRequestGenerator func() (*AuthorizationRequest, error)

// AuthorizationRequest represents an incoming authorization request
type AuthorizationRequest struct {
	ResponseType AuthorizeResponseType
	ClientID     string
	Scope        string
	RedirectURI  string
	State        string

	// Token expiration in seconds. Change if different from default.
	// If type = ResponseTypeToken, this expiration will be for the ACCESS token.
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
	ar := authorizationRequestFromHTTPRequest(r)

	// must have a valid client
	clientData, err := getClientData(ctx, ar.ClientID, s.Storage)
	if err != nil {
		return nil, err
	}
	s.updateRedirectURI(clientData, ar)

	if err := s.validateAuthorizationRequest(ctx, clientData, ar); err != nil {
		return nil, err
	}

	return ar, nil
}

func authorizationRequestFromHTTPRequest(r *http.Request) *AuthorizationRequest {
	return &AuthorizationRequest{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		State:               r.FormValue("state"),
		Scope:               r.FormValue("scope"),
		ResponseType:        AuthorizeResponseType(r.FormValue("response_type")),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: PKCECodeChallengeMethod(r.FormValue("code_challenge_method")),
	}
}

func (s *Server) updateRedirectURI(clientData *ClientData, ar *AuthorizationRequest) {
	clientRedirectURI := clientData.RedirectURI
	URISeparator := s.Config.RedirectURISeparator

	// Set access request redirectURI if it is empty and client has only one redirect URI
	if ar.RedirectURI == "" && firstURI(clientRedirectURI, URISeparator) == clientRedirectURI {
		ar.RedirectURI = firstURI(clientRedirectURI, URISeparator)
	}
}

func (s *Server) validateAuthorizationRequest(ctx context.Context, clientData *ClientData, ar *AuthorizationRequest) error {
	// check redirect uri
	clientRedirectURI := clientData.RedirectURI
	URISeparator := s.Config.RedirectURISeparator
	if err := validateURIList(clientRedirectURI, ar.RedirectURI, URISeparator); err != nil {
		return NewWrappedError(EInvalidRequest, err, "specified redirect_uri not valid for the given client_id")
	}

	// Redirect uri is valid, all future errors will redirect to redirectURI
	if s.Config.AllowedAuthorizeTypes.Exists(ar.ResponseType) {
		ar.Expiration = s.Config.AuthorizationExpiration

		if ar.ResponseType == ResponseTypeCode {
			// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
			if codeChallenge := ar.CodeChallenge; len(codeChallenge) == 0 {
				if s.Config.RequirePKCEForPublicClients && clientData.ClientSecret == "" {
					// https://tools.ietf.org/html/rfc7636#section-4.4.1
					return errorWithRedirect(ar, NewError(EInvalidRequest, "code_challenge (rfc7636) required for public clients"))
				}
			} else {
				codeChallengeMethod := ar.CodeChallengeMethod
				// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
				if len(codeChallengeMethod) == 0 {
					codeChallengeMethod = PKCEPlain
				}
				if codeChallengeMethod != PKCEPlain && codeChallengeMethod != PKCES256 {
					// https://tools.ietf.org/html/rfc7636#section-4.4.1
					return errorWithRedirect(ar, NewError(EInvalidRequest, "code_challenge_method transform algorithm not supported (rfc7636)"))
				}

				// https://tools.ietf.org/html/rfc7636#section-4.2
				if matched := pkceMatcher.MatchString(codeChallenge); !matched {
					return errorWithRedirect(ar, NewError(EInvalidRequest, "code_challenge invalid (rfc7636)"))
				}

				ar.CodeChallenge = codeChallenge
				ar.CodeChallengeMethod = codeChallengeMethod
			}
		}

		return nil
	}

	return errorWithRedirect(ar, NewError(EUnsupportedResponseType, "request type not in server allowed authorize types"))

}

// errors caused by invalid client identifiers or redirect URIs will not cause redirects
// if an error occurs post redirect uri validation, redirect with error in query
// (https://tools.ietf.org/html/rfc6749#section-4.1.2.1)
func errorWithRedirect(ar *AuthorizationRequest, err error) error {
	nisoErr := toInternalError(err)

	nisoErr.SetRedirectURI(ar.RedirectURI)
	nisoErr.SetState(ar.State)

	return nisoErr
}

// HandleHTTPAuthorizeRequest is the main entry point for handling authorization requests.
// This method will always return a Response, even if there was an error processing the request, which should be
// rendered for a user. It may also return an error in the second argument which can be logged by the caller.
func (s *Server) HandleHTTPAuthorizeRequest(ctx context.Context, r *http.Request, isAuthorizedCb AuthRequestAuthorizedCallback) (*Response, error) {
	return s.HandleAuthorizeRequest(
		ctx,
		func() (*AuthorizationRequest, error) {
			return authorizationRequestFromHTTPRequest(r), nil
		},
		isAuthorizedCb,
	)
}

// HandleAuthorizeRequest is the main entry point for handling authorization requests.
// It can take a method which generates the AuthRequest struct to use for the authorization
// This method will always return a Response, even if there was an error processing the request, which should be
// rendered for a user. It may also return an error in the second argument which can be logged by the caller.
func (s *Server) HandleAuthorizeRequest(ctx context.Context, f AuthRequestGenerator, isAuthorizedCb AuthRequestAuthorizedCallback) (*Response, error) {
	ar, err := f()
	if err != nil {
		err = toInternalError(err)

		// AuthorizationRequest generation failed for some reason, see if an AR was returned, if so use it's redirectURI if valid
		// Any errors during this step where we attempt to redirect are ignored in favour of the error that actually
		// occurred when generating the AR
		if ar != nil {
			clientData, clientErr := getClientData(ctx, ar.ClientID, s.Storage)
			if clientErr == nil {
				s.updateRedirectURI(clientData, ar)
				if validationErr := s.validateAuthorizationRequest(ctx, clientData, ar); validationErr == nil {
					err = errorWithRedirect(ar, err)
					return toInternalError(err).AsResponse(), err
				}
			}
		}

		return toInternalError(err).AsResponse(), err
	}

	clientData, err := getClientData(ctx, ar.ClientID, s.Storage)
	if err != nil {
		return toInternalError(err).AsResponse(), err
	}
	s.updateRedirectURI(clientData, ar)
	if err := s.validateAuthorizationRequest(ctx, clientData, ar); err != nil {
		return toInternalError(err).AsResponse(), err
	}

	isAuthorized, err := isAuthorizedCb(ar)
	if err != nil {
		err = errorWithRedirect(ar, NewWrappedError(EServerError, err, "authorization check failed"))
		return toInternalError(err).AsResponse(), err
	}

	if !isAuthorized {
		err = errorWithRedirect(ar, NewError(EAccessDenied, "access denied"))
		return toInternalError(err).AsResponse(), err
	}

	resp, err := s.FinishAuthorizeRequest(ctx, ar)
	if err != nil {
		return toInternalError(err).AsResponse(), err
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
	if ar.ResponseType == ResponseTypeToken {
		// generate token directly
		ret := &AccessRequest{
			GrantType:       GrantTypeImplicit,
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
		return nil, NewWrappedError(EServerError, err, "failed to generate authorize token")

	}
	ret.Code = code

	// save authorization token
	if err = s.Storage.SaveAuthorizeData(ctx, ret); err != nil {
		return nil, NewWrappedError(EServerError, err, "failed to save authorize data")
	}

	// redirect with code
	resp.Data["code"] = ret.Code
	resp.Data["state"] = ret.State
	return resp, nil
}
