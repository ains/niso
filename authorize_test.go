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

	req := makeAuthorizeTestRequest(t, CODE)

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

	req := makeAuthorizeTestRequest(t, CODE)

	ctx := context.TODO()
	ar, err := server.GenerateAuthorizeRequest(ctx, req)
	require.NoError(t, err)

	ar.Authorized = false
	_, err = server.FinishAuthorizeRequest(ctx, ar)
	assertNisoError(
		t,
		err,
		E_ACCESS_DENIED,
		"(access_denied) access denied",
	)

	redirectURI, err := err.(*NisoError).GetRedirectURI()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:14000/appauth?error=access_denied&error_description=access+denied&state=a", redirectURI)
}

func TestAuthorizeInvalidClient(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req := makeAuthorizeTestRequest(t, CODE)
	req.Form.Set("client_id", "invalid")

	ctx := context.TODO()
	_, err := server.GenerateAuthorizeRequest(ctx, req)
	assertNisoError(
		t,
		err,
		E_UNAUTHORIZED_CLIENT,
		"(unauthorized_client) could not find client: client not found",
	)

	redirectURI, err := err.(*NisoError).GetRedirectURI()
	require.NoError(t, err)
	assert.Equal(t, "", redirectURI)
}

func TestAuthorizeInvalidRedirectURI(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{CODE}
	server := newTestServer(config)

	req := makeAuthorizeTestRequest(t, CODE)
	req.Form.Set("redirect_uri", "invalid")

	ctx := context.TODO()
	_, err := server.GenerateAuthorizeRequest(ctx, req)
	assertNisoError(
		t,
		err,
		E_INVALID_REQUEST,
		"(invalid_request) specified redirect_uri not valid for the given client_id: no matching uri found in allowed uri list: http://localhost:14000/appauth / invalid",
	)

	redirectURI, err := err.(*NisoError).GetRedirectURI()
	require.NoError(t, err)
	assert.Equal(t, "", redirectURI)
}

func TestAuthorizeInvalidAuthorizeType(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{}
	server := newTestServer(config)

	req := makeAuthorizeTestRequest(t, CODE)

	ctx := context.TODO()
	_, err := server.GenerateAuthorizeRequest(ctx, req)
	assertNisoError(
		t,
		err,
		E_UNSUPPORTED_RESPONSE_TYPE,
		"(unsupported_response_type) request type not in server allowed authorize types",
	)
}

func TestAuthorizeToken(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAuthorizeTypes = AllowedAuthorizeTypes{TOKEN}
	server := newTestServer(config)

	req := makeAuthorizeTestRequest(t, TOKEN)

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
		assertNisoError(
			t,
			err,
			E_INVALID_REQUEST,
			"(invalid_request) code_challenge (rfc7636) required for public clients",
		)
	}

	// Confidential client works without PKCE
	{
		req := makeAuthorizeTestRequest(t, CODE)

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

	req := makeAuthorizeTestRequest(t, CODE)
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

	req := makeAuthorizeTestRequest(t, CODE)
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

	req := makeAuthorizeTestRequest(t, CODE)
	req.Form.Set("code_challenge", challenge)
	req.Form.Set("code_challenge_method", "invalid")

	ctx := context.TODO()
	_, err := server.GenerateAuthorizeRequest(ctx, req)
	assertNisoError(
		t,
		err,
		E_INVALID_REQUEST,
		"(invalid_request) code_challenge_method transform algorithm not supported (rfc7636)",
	)
}

func newTestServer(config *ServerConfig) *Server {
	server := NewServer(config, NewTestingStorage())
	server.AuthorizeTokenGenerator = &TestingAuthorizeTokenGen{}
	server.AccessTokenGenerator = &TestingAccessTokenGen{}
	return server
}

func makeAuthorizeTestRequest(t *testing.T, responseType AuthorizeResponseType) *http.Request {
	req, err := http.NewRequest("GET", testAuthURL, nil)
	require.NoError(t, err)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(responseType))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")
	return req
}

func assertNisoError(t *testing.T, err error, expectedCode ErrorCode, expectedMessage string) {
	require.EqualError(
		t,
		err,
		expectedMessage,
		"expected %s error",
		string(expectedCode),
	)
	require.IsType(t, &NisoError{}, err, "error should be of type NisoError")
	assert.Equal(t, expectedCode, err.(*NisoError).Code)
}
