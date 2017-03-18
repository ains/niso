package niso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

const (
	clientID     = "test_client"
	clientSecret = "notsecure"
	redirectURI  = "http://localhost/callback"
)

type NisoIntegrationTestSuite struct {
	suite.Suite
	testAuthorizeURL string
	testAccessURL    string
	oauthConfig      *oauth2.Config
}

func (s *NisoIntegrationTestSuite) SetupSuite() {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{AUTHORIZATION_CODE}
	server := newTestServer(config)
	server.Storage = newIntegrationTestStorage()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()
		ar, err := server.GenerateAuthorizeRequest(ctx, r)
		if err != nil {
			WriteErrorResponse(w, err)
			return
		}

		ar.Authorized = true
		resp, err := server.FinishAuthorizeRequest(ctx, ar)
		if err != nil {
			WriteErrorResponse(w, err)
			return
		}

		WriteJSONResponse(w, resp)
	}))
	s.testAuthorizeURL = authServer.URL

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

	return r
}
