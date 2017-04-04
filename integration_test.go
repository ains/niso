package niso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

const (
	clientID     = "test_client"
	clientSecret = "notsecure"
	redirectURI  = "http://localhost/callback"
	testAuthCode = "9999"
)

type NisoIntegrationTestSuite struct {
	suite.Suite
	testAuthorizeURL string
	testAccessURL    string
	oauthConfig      *oauth2.Config
}

func (s *NisoIntegrationTestSuite) SetupSuite() {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{GrantTypeAuthorizationCode}
	server := newTestServer(config)
	server.Storage = newIntegrationTestStorage()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()

		resp, err := server.HandleHTTPAuthorizeRequest(
			ctx,
			r,
			func(_ *AuthorizationRequest) (bool, error) { return true, nil },
		)
		if err != nil {
			s.T().Logf("Error handling authorize request %v", err)
		}

		WriteJSONResponse(w, resp)
	}))
	s.testAuthorizeURL = authServer.URL

	accessServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()
		resp, err := server.HandleHTTPAccessRequest(
			ctx,
			r,
			func(_ *AccessRequest) (bool, error) { return true, nil },
		)
		if err != nil {
			s.T().Logf("Error handling authorize request %v", err)
		}

		WriteJSONResponse(w, resp)
	}))
	s.testAccessURL = accessServer.URL

	s.oauthConfig = newOAuthConfig(s.testAuthorizeURL, s.testAccessURL)
}

func (s *NisoIntegrationTestSuite) TestAuthCodeCallbackSuccess() {
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authCodeURL := s.oauthConfig.AuthCodeURL("kappa")

	resp, err := client.Get(authCodeURL)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), 302, resp.StatusCode)
	assert.Equal(s.T(), "http://localhost/callback?code=1&state=kappa", resp.Header["Location"][0])
}

func (s *NisoIntegrationTestSuite) TestAuthCodeCallbackBadRedirectURI() {
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	config := *s.oauthConfig
	config.RedirectURL = "http://invalid.redirect.uri/"
	authCodeURL := config.AuthCodeURL("kappa")

	resp, err := client.Get(authCodeURL)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), 400, resp.StatusCode)
}

func (s *NisoIntegrationTestSuite) TestAuthCodeCallbackBadResponseType() {
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authCodeURL := s.oauthConfig.AuthCodeURL("kappa", oauth2.SetAuthURLParam("response_type", "garbage"))

	resp, err := client.Get(authCodeURL)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), 302, resp.StatusCode)
	assert.Equal(s.T(), "http://localhost/callback?error=unsupported_response_type&error_description=request+type+not+in+server+allowed+authorize+types&state=kappa", resp.Header["Location"][0])
}

func (s *NisoIntegrationTestSuite) TestAccessTokenExchangeSuccess() {
	tok, err := s.oauthConfig.Exchange(context.TODO(), testAuthCode)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "r1", tok.RefreshToken)
	assert.Equal(s.T(), "1", tok.AccessToken)
}

func (s *NisoIntegrationTestSuite) TestAccessTokenExchangeFail() {
	_, err := s.oauthConfig.Exchange(context.TODO(), "invalid")
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "invalid_grant")
}

func TestNisoIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(NisoIntegrationTestSuite))
}

func newOAuthConfig(authURL string, tokenURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"scope1", "scope2"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}
}

func newIntegrationTestStorage() Storage {
	r := &TestingStorage{
		clients:   make(map[string]*ClientData),
		authorize: make(map[string]*AuthorizeData),
		access:    make(map[string]*AccessData),
		refresh:   make(map[string]*RefreshTokenData),
	}

	r.clients[clientID] = &ClientData{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}

	r.authorize[testAuthCode] = &AuthorizeData{
		ClientID:    clientID,
		Code:        testAuthCode,
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectURI: redirectURI,
	}

	return r
}
