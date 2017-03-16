package niso

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/url"
	"testing"
)

var testAuthUrl string = "http://localhost:14000/appauth"

func TestAuthorizeCode(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthUrl, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	ctx := context.TODO()
	ar, err := server.GenerateAuthorizeRequest(ctx, req)
	require.NoError(t, err)

	ar.Authorized = true
	resp, err := server.FinishAuthorizeRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, REDIRECT, resp.Type, "response type should be a redirect")
	assert.Equal(t, "1", resp.Data["code"], "incorrect authorization code")
}

func TestAuthorizeToken(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{TOKEN}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthUrl, nil)
	require.NoError(t, err)

	req.Form = make(url.Values)
	req.Form.Set("response_type", string(TOKEN))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	ctx := context.TODO()
	ar, err := server.GenerateAuthorizeRequest(ctx, req)
	require.NoError(t, err)

	ar.Authorized = true
	resp, err := server.FinishAuthorizeRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, REDIRECT, resp.Type, "response type should be a redirect")
	assert.True(t, resp.redirectInFragment, "response should be a redirect with fragment")
	assert.Equal(t, "1", resp.Data["access_token"], "incorrect access_token")
}

func TestAuthorizeCodePKCERequired(t *testing.T) {
	config := NewServerConfig()
	config.RequirePKCEForPublicClients = true
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	// Public client returns an error
	{
		req, err := http.NewRequest("GET", testAuthUrl, nil)
		require.NoError(t, err)
		req.Form = make(url.Values)
		req.Form.Set("response_type", string(CODE))
		req.Form.Set("state", "a")
		req.Form.Set("client_id", "public-client")

		ctx := context.TODO()
		_, err = server.GenerateAuthorizeRequest(ctx, req)
		require.EqualError(
			t,
			err,
			"(invalid_request) code_challenge (rfc7636) required for public clients",
			"expected invalid_request error",
		)
		require.IsType(t, &NisoError{}, err, "error should be of type NisoError")
		assert.Equal(t, E_INVALID_REQUEST, err.(*NisoError).ErrorCode)
	}

	// Confidential client works without PKCE
	{
		req, err := http.NewRequest("GET", testAuthUrl, nil)
		require.NoError(t, err)
		req.Form = make(url.Values)
		req.Form.Set("response_type", string(CODE))
		req.Form.Set("state", "a")
		req.Form.Set("client_id", "1234")

		ctx := context.TODO()
		ar, err := server.GenerateAuthorizeRequest(ctx, req)
		require.NoError(t, err)

		ar.Authorized = true
		resp, err := server.FinishAuthorizeRequest(ctx, ar)
		require.NoError(t, err)

		assert.Equal(t, REDIRECT, resp.Type, "response type should be a redirect")
		assert.Equal(t, "1", resp.Data["code"], "incorrect authorization code")
	}
}

func TestAuthorizeCodePKCEPlain(t *testing.T) {
	challenge := "12345678901234567890123456789012345678901234567890"

	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthUrl, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")
	req.Form.Set("code_challenge", challenge)

	ctx := context.TODO()
	ar, err := server.GenerateAuthorizeRequest(ctx, req)
	require.NoError(t, err)

	ar.Authorized = true
	resp, err := server.FinishAuthorizeRequest(ctx, ar)
	require.NoError(t, err)

	code := resp.Data["code"].(string)
	assert.Equal(t, REDIRECT, resp.Type, "response type should be a redirect")
	assert.Equal(t, "1", code, "incorrect authorization code")

	token, err := server.Storage.GetAuthorizeData(ctx, code)
	require.NoError(t, err)

	assert.Equal(t, challenge, token.CodeChallenge)
	assert.Equal(t, "plain", token.CodeChallengeMethod)
}

func TestAuthorizeCodePKCES256(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthUrl, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")
	req.Form.Set("code_challenge", challenge)
	req.Form.Set("code_challenge_method", "S256")

	ctx := context.TODO()
	ar, err := server.GenerateAuthorizeRequest(ctx, req)
	require.NoError(t, err)

	ar.Authorized = true
	resp, err := server.FinishAuthorizeRequest(ctx, ar)
	require.NoError(t, err)

	code := resp.Data["code"].(string)
	assert.Equal(t, REDIRECT, resp.Type, "response type should be a redirect")
	assert.Equal(t, "1", code, "incorrect authorization code")

	token, err := server.Storage.GetAuthorizeData(ctx, code)
	require.NoError(t, err)

	assert.Equal(t, challenge, token.CodeChallenge)
	assert.Equal(t, "S256", token.CodeChallengeMethod)
}

func newTestServer(config *ServerConfig) *Server {
	server := NewServer(config, NewTestingStorage())
	server.AuthorizeTokenGenerator = &TestingAuthorizeTokenGen{}
	server.AccessTokenGenerator = &TestingAccessTokenGen{}
	return server
}
