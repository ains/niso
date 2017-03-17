package niso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// GrantType is the type for OAuth param `grant_type`
type GrantType string

// https://tools.ietf.org/html/rfc6749#appendix-A.10
const (
	AUTHORIZATION_CODE GrantType = "authorization_code"
	REFRESH_TOKEN      GrantType = "refresh_token"
	PASSWORD           GrantType = "password"
	CLIENT_CREDENTIALS GrantType = "client_credentials"
	ASSERTION          GrantType = "assertion"
	IMPLICIT           GrantType = "__implicit"
)

// AccessRequest is a request for access tokens
type AccessRequest struct {
	GrantType     GrantType
	Code          string
	ClientData    *ClientData
	AuthorizeData *AuthorizeData

	PreviousRefreshToken *RefreshTokenData

	RedirectURI   string
	Scope         string
	Username      string
	Password      string
	AssertionType string
	Assertion     string

	// Set if request is Authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default
	Expiration int32

	// Set if a refresh token should be generated
	GenerateRefresh bool

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HTTPRequest *http.Request for special use
	HTTPRequest *http.Request

	// Optional code_verifier as described in rfc7636
	CodeVerifier string
}

// AccessData represents an access grant (tokens, expiration, client, etc)
type AccessData struct {
	// ClientData information
	ClientData *ClientData

	// Access token
	AccessToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectURI string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// RefreshTokenData represents an issued refresh token, which should be persisted to storage in it's entirety
type RefreshTokenData struct {
	// ID of the client used to issue this refresh token
	ClientID string

	// Refresh token string
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Time at which refresh token was created
	CreatedAt time.Time

	// Redirect Uri from request
	RedirectURI string

	// Scope requested for this refresh token
	Scope string

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// IsExpired returns true if access expired
func (d *AccessData) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpiredAt returns true if access expires at time 't'
func (d *AccessData) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *AccessData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AccessTokenGenerator generates access tokens and refresh tokens
type AccessTokenGenerator interface {
	GenerateAccessToken(ar *AccessRequest) (accessToken string, err error)
	GenerateRefreshToken(ar *AccessRequest) (refreshToken string, err error)
}

// GenerateAccessRequest handles access token requests. Generates an AccessRequest from a HTTP request.
func (s *Server) GenerateAccessRequest(ctx context.Context, r *http.Request) (*AccessRequest, error) {
	// Only allow GET (when AllowGetAccessRequest set) or POST
	if r.Method == "GET" && !s.Config.AllowGetAccessRequest {
		return nil, NewNisoError(E_INVALID_REQUEST, errors.New("GET method not allowed for access requests"))
	} else if r.Method != "POST" {
		return nil, NewNisoError(E_INVALID_REQUEST, errors.New("access requests must POST verb"))
	}

	err := r.ParseForm()
	if err != nil {
		return nil, NewNisoError(E_INVALID_REQUEST, errors.Wrap(err, "failed to parse access request form body"))
	}

	grantType := GrantType(r.Form.Get("grant_type"))
	if s.Config.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAuthorizationCodeRequest(ctx, r)
		case REFRESH_TOKEN:
			return s.handleRefreshTokenRequest(ctx, r)
		case PASSWORD:
			return s.handlePasswordRequest(ctx, r)
		case CLIENT_CREDENTIALS:
			return s.handleClientCredentialsRequest(ctx, r)
		case ASSERTION:
			return s.handleAssertionRequest(ctx, r)
		}
	}

	return nil, NewNisoError(E_UNSUPPORTED_GRANT_TYPE, errors.New("unsupported grant type"))
}

func (s *Server) handleAuthorizationCodeRequest(ctx context.Context, r *http.Request) (*AccessRequest, error) {
	// get client authentication
	auth, err := getClientAuthFromRequest(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		return nil, NewNisoError(E_INVALID_REQUEST, errors.Wrap(err, "failed to get client authentication"))
	}

	// generate access token
	ret := &AccessRequest{
		GrantType:       AUTHORIZATION_CODE,
		Code:            r.Form.Get("code"),
		CodeVerifier:    r.Form.Get("code_verifier"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HTTPRequest:     r,
	}

	// "code" is required
	if ret.Code == "" {
		return nil, NewNisoError(E_INVALID_GRANT, errors.New("no authorization code provided"))
	}

	// must have a valid client
	clientData, err := getClientDataFromBasicAuth(ctx, auth, s.Storage)
	if err != nil {
		return nil, err
	}
	ret.ClientData = clientData

	// must be a valid authorization code
	ret.AuthorizeData, err = s.Storage.GetAuthorizeData(ctx, ret.Code)
	if err != nil {
		return nil, NewNisoError(E_INVALID_GRANT, errors.Wrap(err, "could not load data for authorization code"))
	}

	// authorization code must be from the client id of current request
	if ret.AuthorizeData.ClientData.ClientID != ret.ClientData.ClientID {
		return nil, NewNisoError(E_INVALID_GRANT, errors.New("invalid client id for authorization code"))
	}

	// authorization code must not be expired
	if ret.AuthorizeData.IsExpiredAt(s.Now()) {
		return nil, NewNisoError(E_INVALID_GRANT, errors.New("authorization code expired"))
	}

	// Verify PKCE, if present in the authorization data
	if len(ret.AuthorizeData.CodeChallenge) > 0 {
		// https://tools.ietf.org/html/rfc7636#section-4.1
		if matched := pkceMatcher.MatchString(ret.CodeVerifier); !matched {
			return nil, NewNisoError(E_INVALID_REQUEST, errors.New("code_verifier invalid (rfc7636)"))
		}

		// https: //tools.ietf.org/html/rfc7636#section-4.6
		codeVerifier := ""
		switch ret.AuthorizeData.CodeChallengeMethod {
		case "", PKCE_PLAIN:
			codeVerifier = ret.CodeVerifier
		case PKCE_S256:
			hash := sha256.Sum256([]byte(ret.CodeVerifier))
			codeVerifier = base64.RawURLEncoding.EncodeToString(hash[:])
		default:
			return nil, NewNisoError(E_INVALID_REQUEST, errors.New("code_challenge_method transform algorithm not supported (rfc7636)"))
		}
		if codeVerifier != ret.AuthorizeData.CodeChallenge {
			return nil, NewNisoError(E_INVALID_GRANT, errors.New("code_verifier failed comparison with code_challenge"))
		}
	}

	// set rest of data
	ret.Scope = ret.AuthorizeData.Scope
	ret.UserData = ret.AuthorizeData.UserData

	return ret, nil
}

func extraScopes(accessScopes, refreshScopes string) bool {
	accessScopesLists := strings.Split(accessScopes, ",")
	refreshScopesLists := strings.Split(refreshScopes, ",")

	accessMaps := make(map[string]int)

	for _, scope := range accessScopesLists {
		if scope == "" {
			continue
		}
		accessMaps[scope] = 1
	}

	for _, scope := range refreshScopesLists {
		if scope == "" {
			continue
		}
		if _, ok := accessMaps[scope]; !ok {
			return true
		}
	}
	return false
}

func (s *Server) handleRefreshTokenRequest(ctx context.Context, r *http.Request) (*AccessRequest, error) {
	// get client authentication
	auth, err := getClientAuthFromRequest(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		return nil, err
	}

	// generate access token
	req := &AccessRequest{
		GrantType:       REFRESH_TOKEN,
		Code:            r.Form.Get("refresh_token"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HTTPRequest:     r,
	}

	// "refresh_token" is required
	if req.Code == "" {
		return nil, NewNisoError(E_INVALID_GRANT, errors.New("no refresh token provided"))
	}

	// must have a valid client
	clientData, err := getClientDataFromBasicAuth(ctx, auth, s.Storage)
	if err != nil {
		return nil, err
	}
	req.ClientData = clientData

	// must be a valid refresh code
	req.PreviousRefreshToken, err = s.Storage.GetRefreshTokenData(ctx, req.Code)
	if err != nil {
		return nil, NewNisoError(E_INVALID_GRANT, errors.Wrap(err, "failed to get refresh token data from storage"))
	}

	// client must be the same as the previous token
	if req.PreviousRefreshToken.ClientID != req.ClientData.ClientID {
		return nil, NewNisoError(E_INVALID_CLIENT, errors.New("request client id must be the same from previous token"))
	}

	// set rest of data
	req.RedirectURI = req.PreviousRefreshToken.RedirectURI
	req.UserData = req.PreviousRefreshToken.UserData
	if req.Scope == "" {
		req.Scope = req.PreviousRefreshToken.Scope
	}

	if extraScopes(req.PreviousRefreshToken.Scope, req.Scope) {
		return nil, NewNisoError(E_ACCESS_DENIED, errors.New("the requested scope must not include any scope not originally granted by the resource owner"))
	}

	return req, nil
}

func (s *Server) handlePasswordRequest(ctx context.Context, r *http.Request) (*AccessRequest, error) {
	// get client authentication
	auth, err := getClientAuthFromRequest(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		return nil, err
	}

	// generate access token
	ret := &AccessRequest{
		GrantType:       PASSWORD,
		Username:        r.Form.Get("username"),
		Password:        r.Form.Get("password"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HTTPRequest:     r,
	}

	// "username" and "password" is required
	if ret.Username == "" {
		return nil, NewNisoError(E_INVALID_GRANT, errors.New("username field not set"))
	}
	if ret.Password == "" {
		return nil, NewNisoError(E_INVALID_GRANT, errors.New("password field not set"))
	}

	// must have a valid client
	clientData, err := getClientDataFromBasicAuth(ctx, auth, s.Storage)
	if err != nil {
		return nil, err
	}
	ret.ClientData = clientData

	// set redirect uri
	ret.RedirectURI = firstURI(ret.ClientData.RedirectURI, s.Config.RedirectURISeparator)

	return ret, nil
}

func (s *Server) handleClientCredentialsRequest(ctx context.Context, r *http.Request) (*AccessRequest, error) {
	// get client authentication
	auth, err := getClientAuthFromRequest(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		return nil, err
	}

	// generate access token
	ret := &AccessRequest{
		GrantType:       CLIENT_CREDENTIALS,
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: false,
		Expiration:      s.Config.AccessExpiration,
		HTTPRequest:     r,
	}

	clientData, err := getClientDataFromBasicAuth(ctx, auth, s.Storage)
	if err != nil {
		return nil, err
	}
	ret.ClientData = clientData

	// set redirect uri
	ret.RedirectURI = firstURI(ret.ClientData.RedirectURI, s.Config.RedirectURISeparator)

	return ret, nil
}

func (s *Server) handleAssertionRequest(ctx context.Context, r *http.Request) (*AccessRequest, error) {
	// get client authentication
	auth, err := getClientAuthFromRequest(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		return nil, err
	}

	// generate access token
	ret := &AccessRequest{
		GrantType:       ASSERTION,
		Scope:           r.Form.Get("scope"),
		AssertionType:   r.Form.Get("assertion_type"),
		Assertion:       r.Form.Get("assertion"),
		GenerateRefresh: false, // assertion should NOT generate a refresh token, per the RFC
		Expiration:      s.Config.AccessExpiration,
		HTTPRequest:     r,
	}

	// "assertion_type" and "assertion" is required
	// "username" and "password" is required
	if ret.AssertionType == "" {
		return nil, NewNisoError(E_INVALID_GRANT, errors.New("assertion_type field not set"))
	}
	if ret.Assertion == "" {
		return nil, NewNisoError(E_INVALID_GRANT, errors.New("assertion field not set"))
	}

	// must have a valid client
	clientData, err := getClientDataFromBasicAuth(ctx, auth, s.Storage)
	if err != nil {
		return nil, err
	}
	ret.ClientData = clientData

	// set redirect uri
	ret.RedirectURI = firstURI(ret.ClientData.RedirectURI, s.Config.RedirectURISeparator)

	return ret, nil
}

// FinishAccessRequest processes a given access request and returns the response or error to return to the user
func (s *Server) FinishAccessRequest(ctx context.Context, ar *AccessRequest) (*Response, error) {
	resp := NewResponse()

	redirectURI := ar.RedirectURI
	// Get redirect uri from AccessRequest if it's there (e.g., refresh token request)
	if ar.RedirectURI != "" {
		redirectURI = ar.RedirectURI
	}

	if ar.Authorized {
		var ret *AccessData
		var err error

		// generate access token
		ret = &AccessData{
			ClientData:  ar.ClientData,
			RedirectURI: redirectURI,
			CreatedAt:   s.Now(),
			ExpiresIn:   ar.Expiration,
			UserData:    ar.UserData,
			Scope:       ar.Scope,
		}

		// generate access token
		ret.AccessToken, err = s.AccessTokenGenerator.GenerateAccessToken(ar)
		if err != nil {
			return nil, NewNisoError(E_SERVER_ERROR, errors.Wrap(err, "failed to generate access token"))
		}

		if ar.GenerateRefresh {
			// Generate Refresh Token
			rt := &RefreshTokenData{
				ClientID:  ar.ClientData.ClientID,
				CreatedAt: s.Now(),
				ExpiresIn: ar.Expiration,
				UserData:  ar.UserData,
				Scope:     ar.Scope,
			}
			rt.RefreshToken, err = s.AccessTokenGenerator.GenerateRefreshToken(ar)
			if err != nil {
				return nil, NewNisoError(E_SERVER_ERROR, errors.Wrap(err, "failed to generate refresh token"))
			}

			// Save Refresh Token
			if err := s.Storage.SaveRefreshTokenData(ctx, rt); err != nil {
				return nil, NewNisoError(E_SERVER_ERROR, errors.Wrap(err, "could not save new refresh token data"))
			}

			// Attach refresh token string to output
			resp.Data["refresh_token"] = rt.RefreshToken
		}

		// save access token
		if err = s.Storage.SaveAccessData(ctx, ret); err != nil {
			return nil, NewNisoError(E_SERVER_ERROR, errors.Wrap(err, "failed to save access data"))
		}

		// remove authorization token
		if ar.AuthorizeData != nil {
			s.Storage.DeleteAuthorizeData(ctx, ar.AuthorizeData.Code)
		}

		// remove previous access token
		if ar.PreviousRefreshToken != nil {
			s.Storage.DeleteRefreshTokenData(ctx, ar.PreviousRefreshToken.RefreshToken)
		}

		// output data
		resp.Data["access_token"] = ret.AccessToken
		resp.Data["token_type"] = s.Config.TokenType
		resp.Data["expires_in"] = ret.ExpiresIn

		if ar.Scope != "" {
			resp.Data["scope"] = ar.Scope
		}
	} else {
		return nil, NewNisoError(E_ACCESS_DENIED, errors.New("access denied"))
	}

	return resp, nil
}
