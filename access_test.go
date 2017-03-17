package niso

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessAuthorizationCode(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{AUTHORIZATION_CODE}
	server := newTestServer(config)

	req, err := http.NewRequest("POST", testAuthURL, nil)
	require.NoError(t, err)
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	ctx := context.TODO()
	ar, err := server.GenerateAccessRequest(ctx, req)
	require.NoError(t, err)
	ar.Authorized = true
	resp, err := server.FinishAccessRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, DATA, resp.responseType)
	assert.Equal(t, "1", resp.Data["access_token"])
	assert.Equal(t, "r1", resp.Data["refresh_token"])
}

func TestAccessRefreshToken(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{REFRESH_TOKEN}
	server := newTestServer(config)

	req, err := http.NewRequest("POST", testAuthURL, nil)
	require.NoError(t, err)
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "r9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	ctx := context.TODO()
	ar, err := server.GenerateAccessRequest(ctx, req)
	require.NoError(t, err)
	ar.Authorized = true
	resp, err := server.FinishAccessRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, DATA, resp.responseType)
	assert.Equal(t, "1", resp.Data["access_token"])
	assert.Equal(t, "r1", resp.Data["refresh_token"])
}

func TestAccessPassword(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{PASSWORD}
	server := newTestServer(config)

	req, err := http.NewRequest("POST", testAuthURL, nil)
	require.NoError(t, err)
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(PASSWORD))
	req.Form.Set("username", "testing")
	req.Form.Set("password", "testing")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	ctx := context.TODO()
	ar, err := server.GenerateAccessRequest(ctx, req)
	require.NoError(t, err)
	ar.Authorized = ar.Username == "testing" && ar.Password == "testing"
	resp, err := server.FinishAccessRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, DATA, resp.responseType)
	assert.Equal(t, "1", resp.Data["access_token"])
	assert.Equal(t, "r1", resp.Data["refresh_token"])
}

func TestAccessClientCredentials(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{CLIENT_CREDENTIALS}
	server := newTestServer(config)

	req, err := http.NewRequest("POST", testAuthURL, nil)
	require.NoError(t, err)

	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	ctx := context.TODO()
	ar, err := server.GenerateAccessRequest(ctx, req)
	require.NoError(t, err)
	ar.Authorized = true
	resp, err := server.FinishAccessRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, DATA, resp.responseType)
	assert.Equal(t, "1", resp.Data["access_token"])
	// Refresh token should not be generated
	assert.NotContains(t, resp.Data, "refresh_token")
}

func TestExtraScopes(t *testing.T) {
	assert.False(t, extraScopes("", ""), "extraScopes returned true with empty scopes")
	assert.False(t, extraScopes("a", ""), "extraScopes returned true with fewer scopes")
	assert.False(t, extraScopes("a,b", "b,a"), "extraScopes returned true with matching scopes")

	assert.True(t, extraScopes("a,b", "b,a,c"), "extraScopes returned false with extra scopes")
	assert.True(t, extraScopes("", "b,a,c"), "extraScopes returned false with extra scopes")
}

func TestAccessAuthorizationCodePKCE(t *testing.T) {
	testcases := map[string]struct {
		Challenge       string
		ChallengeMethod PKCECodeChallengeMethod
		Verifier        string
		ExpectedError   ErrorCode
	}{
		"good, plain": {
			Challenge: "12345678901234567890123456789012345678901234567890",
			Verifier:  "12345678901234567890123456789012345678901234567890",
		},
		"bad, plain": {
			Challenge:     "12345678901234567890123456789012345678901234567890",
			Verifier:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError: E_INVALID_GRANT,
		},
		"good, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: PKCE_S256,
			Verifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		"bad, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: PKCE_S256,
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError:   E_INVALID_GRANT,
		},
		"missing from storage": {
			Challenge: "",
			Verifier:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
	}
	ctx := context.TODO()

	for _, test := range testcases {
		testStorage := NewTestingStorage()
		config := NewServerConfig()
		config.AllowedAccessTypes = AllowedAccessTypes{AUTHORIZATION_CODE}
		server := newTestServer(config)
		server.Storage.SaveAuthorizeData(ctx, &AuthorizeData{
			ClientData:          testStorage.clients["public-client"],
			Code:                "pkce-code",
			ExpiresIn:           3600,
			CreatedAt:           time.Now(),
			RedirectURI:         testAuthURL,
			CodeChallenge:       test.Challenge,
			CodeChallengeMethod: PKCECodeChallengeMethod(test.ChallengeMethod),
		})

		req, err := http.NewRequest("POST", testAuthURL, nil)
		require.NoError(t, err)
		req.SetBasicAuth("public-client", "")

		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
		req.Form.Set("code", "pkce-code")
		req.Form.Set("state", "a")
		req.Form.Set("code_verifier", test.Verifier)
		req.PostForm = make(url.Values)

		ar, err := server.GenerateAccessRequest(ctx, req)
		if test.ExpectedError != "" {
			require.Error(t, err)
			require.IsType(t, &NisoError{}, err, "error should be of type NisoError")
			assert.Equal(t, test.ExpectedError, err.(*NisoError).Code)
		} else {
			require.NoError(t, err)

			ar.Authorized = true
			resp, err := server.FinishAccessRequest(ctx, ar)
			require.NoError(t, err)

			assert.Equal(t, DATA, resp.responseType)
			assert.Equal(t, "1", resp.Data["access_token"])
			assert.Equal(t, "r1", resp.Data["refresh_token"])
		}
	}
}
