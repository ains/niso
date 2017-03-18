package niso

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testAuthURL = "http://localhost:14000/appauth"

func TestAuthorizeCode(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
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

	assert.Equal(t, REDIRECT, resp.responseType, "response type should be a redirect")
	assert.Equal(t, "1", resp.Data["code"], "incorrect authorization code")
}

func TestAuthorizeCodeAccessDenied(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	ctx := context.TODO()
	ar, err := server.GenerateAuthorizeRequest(ctx, req)
	require.NoError(t, err)

	ar.Authorized = false
	_, err = server.FinishAuthorizeRequest(ctx, ar)
	require.EqualError(
		t,
		err,
		"(access_denied) access denied",
		"expected access_denied error",
	)
	require.IsType(t, &NisoError{}, err, "error should be of type NisoError")
	assert.Equal(t, E_ACCESS_DENIED, err.(*NisoError).Code)
	redirectURI, err := err.(*NisoError).GetRedirectURI()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:14000/appauth?error=access_denied&error_description=access+denied&state=a", redirectURI)}

func TestAuthorizeInvalidClient(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "invalid")
	req.Form.Set("state", "a")

	ctx := context.TODO()
	_, err = server.GenerateAuthorizeRequest(ctx, req)
	require.EqualError(
		t,
		err,
		"(unauthorized_client) could not find client: client not found",
		"expected unauthorized_client error",
	)
	require.IsType(t, &NisoError{}, err, "error should be of type NisoError")
	assert.Equal(t, E_UNAUTHORIZED_CLIENT, err.(*NisoError).Code)
	redirectURI, err := err.(*NisoError).GetRedirectURI()
	require.NoError(t, err)
	assert.Equal(t, "", redirectURI)
}

func TestAuthorizeInvalidRedirectURI(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("redirect_uri", "invalid")
	req.Form.Set("state", "a")

	ctx := context.TODO()
	_, err = server.GenerateAuthorizeRequest(ctx, req)
	require.EqualError(
		t,
		err,
		"(invalid_request) specified redirect_uri not valid for the given client_id: no matching uri found in allowed uri list: http://localhost:14000/appauth / invalid",
		"expected invalid_request error",
	)
	require.IsType(t, &NisoError{}, err, "error should be of type NisoError")
	assert.Equal(t, E_INVALID_REQUEST, err.(*NisoError).Code)
	redirectURI, err := err.(*NisoError).GetRedirectURI()
	require.NoError(t, err)
	assert.Equal(t, "", redirectURI)
}

func TestAuthorizeInvalidAuthorizeType(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	ctx := context.TODO()
	_, err = server.GenerateAuthorizeRequest(ctx, req)
	require.EqualError(
		t,
		err,
		"(unsupported_response_type) request type not in server allowed authorize types",
		"expected unsupported_response_type error",
	)
	require.IsType(t, &NisoError{}, err, "error should be of type NisoError")
	assert.Equal(t, E_UNSUPPORTED_RESPONSE_TYPE, err.(*NisoError).Code)
}

func TestAuthorizeToken(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{TOKEN}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
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

	assert.Equal(t, REDIRECT, resp.responseType, "response type should be a redirect")
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
		req, err := http.NewRequest("GET", testAuthURL, nil)
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
		assert.Equal(t, E_INVALID_REQUEST, err.(*NisoError).Code)
	}

	// Confidential client works without PKCE
	{
		req, err := http.NewRequest("GET", testAuthURL, nil)
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

		assert.Equal(t, REDIRECT, resp.responseType, "response type should be a redirect")
		assert.Equal(t, "1", resp.Data["code"], "incorrect authorization code")
	}
}

func TestAuthorizeCodePKCEPlain(t *testing.T) {
	challenge := "12345678901234567890123456789012345678901234567890"

	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
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
	assert.Equal(t, REDIRECT, resp.responseType, "response type should be a redirect")
	assert.Equal(t, "1", code, "incorrect authorization code")

	token, err := server.Storage.GetAuthorizeData(ctx, code)
	require.NoError(t, err)

	assert.Equal(t, challenge, token.CodeChallenge)
	assert.Equal(t, PKCE_PLAIN, token.CodeChallengeMethod)
}

func TestAuthorizeCodePKCES256(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
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
	assert.Equal(t, REDIRECT, resp.responseType, "response type should be a redirect")
	assert.Equal(t, "1", code, "incorrect authorization code")

	token, err := server.Storage.GetAuthorizeData(ctx, code)
	require.NoError(t, err)

	assert.Equal(t, challenge, token.CodeChallenge)
	assert.Equal(t, PKCE_S256, token.CodeChallengeMethod)
}

func TestAuthorizeCodeInvalidChallengeMethod(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("GET", testAuthURL, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")
	req.Form.Set("code_challenge", challenge)
	req.Form.Set("code_challenge_method", "invalid")

	ctx := context.TODO()
	_, err = server.GenerateAuthorizeRequest(ctx, req)
	require.EqualError(
		t,
		err,
		"(invalid_request) code_challenge_method transform algorithm not supported (rfc7636)",
		"expected invalid_request error",
	)
	require.IsType(t, &NisoError{}, err, "error should be of type NisoError")
	assert.Equal(t, E_INVALID_REQUEST, err.(*NisoError).Code)
}


func newTestServer(config *ServerConfig) *Server {
	server := NewServer(config, NewTestingStorage())
	server.AuthorizeTokenGenerator = &TestingAuthorizeTokenGen{}
	server.AccessTokenGenerator = &TestingAccessTokenGen{}
	return server
}
