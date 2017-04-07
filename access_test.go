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
	config.AllowedAccessTypes = AllowedAccessTypes{GrantTypeAuthorizationCode}
	server := newTestServer(config)

	req := makeTestRequest(t, GrantTypeAuthorizationCode)
	req.Form.Set("code", "9999")
	req.Form.Set("state", "a")

	ctx := context.TODO()
	ar, err := server.GenerateAccessRequest(ctx, req)
	require.NoError(t, err)

	resp, err := server.FinishAccessRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, DATA, resp.responseType)
	assert.Equal(t, "1", resp.Data["access_token"])
	assert.Equal(t, "r1", resp.Data["refresh_token"])
}

func TestAccessRefreshToken(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{GrantTypeRefreshToken}
	server := newTestServer(config)

	req := makeTestRequest(t, GrantTypeRefreshToken)
	req.Form.Set("refresh_token", "r9999")
	req.Form.Set("state", "a")

	ctx := context.TODO()
	ar, err := server.GenerateAccessRequest(ctx, req)
	require.NoError(t, err)

	resp, err := server.FinishAccessRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, DATA, resp.responseType)
	assert.Equal(t, "1", resp.Data["access_token"])
	assert.Equal(t, "r1", resp.Data["refresh_token"])
}

func TestAccessPassword(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{GrantTypePassword}
	server := newTestServer(config)

	req := makeTestRequest(t, GrantTypePassword)
	req.Form.Set("username", "testing")
	req.Form.Set("password", "testing")
	req.Form.Set("state", "a")

	resp, err := server.HandleHTTPAccessRequest(
		req,
		func(ar *AccessRequest) (bool, error) {
			return ar.Username == "testing" && ar.Password == "testing", nil
		},
	)
	require.NoError(t, err)

	assert.Equal(t, DATA, resp.responseType)
	assert.Equal(t, "1", resp.Data["access_token"])
	assert.Equal(t, "r1", resp.Data["refresh_token"])
}

func TestAccessClientCredentials(t *testing.T) {
	config := NewServerConfig()
	config.AllowedAccessTypes = AllowedAccessTypes{GrantTypeClientCredentials}
	server := newTestServer(config)

	req := makeTestRequest(t, GrantTypeClientCredentials)
	req.Form.Set("state", "a")

	ctx := context.TODO()
	ar, err := server.GenerateAccessRequest(ctx, req)
	require.NoError(t, err)

	resp, err := server.FinishAccessRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, DATA, resp.responseType)
	assert.Equal(t, "1", resp.Data["access_token"])
	// Refresh token should not be generated
	assert.NotContains(t, resp.Data, "refresh_token")
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
			ExpectedError: EInvalidGrant,
		},
		"good, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: PKCES256,
			Verifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		"bad, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: PKCES256,
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError:   EInvalidGrant,
		},
		"missing from storage": {
			Challenge: "",
			Verifier:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
	}
	ctx := context.TODO()

	for _, test := range testcases {
		config := NewServerConfig()
		config.AllowedAccessTypes = AllowedAccessTypes{GrantTypeAuthorizationCode}
		server := newTestServer(config)
		server.Storage.SaveAuthorizeData(ctx, &AuthorizationData{
			ClientID:            "public-client",
			Code:                "pkce-code",
			ExpiresIn:           3600,
			CreatedAt:           time.Now(),
			RedirectURI:         testAuthURL,
			CodeChallenge:       test.Challenge,
			CodeChallengeMethod: PKCECodeChallengeMethod(test.ChallengeMethod),
		})

		req := makeTestRequest(t, GrantTypeAuthorizationCode)
		req.SetBasicAuth("public-client", "")
		req.Form.Set("grant_type", string(GrantTypeAuthorizationCode))
		req.Form.Set("code", "pkce-code")
		req.Form.Set("state", "a")
		req.Form.Set("code_verifier", test.Verifier)

		ar, err := server.GenerateAccessRequest(ctx, req)
		if test.ExpectedError != "" {
			require.Error(t, err)
			require.IsType(t, &Error{}, err, "error should be of type NisoError")
			assert.Equal(t, test.ExpectedError, err.(*Error).Code)
		} else {
			require.NoError(t, err)

			resp, err := server.FinishAccessRequest(ctx, ar)
			require.NoError(t, err)

			assert.Equal(t, DATA, resp.responseType)
			assert.Equal(t, "1", resp.Data["access_token"])
			assert.Equal(t, "r1", resp.Data["refresh_token"])
		}
	}
}

func makeTestRequest(t *testing.T, grantType GrantType) *http.Request {
	req, err := http.NewRequest("POST", testAuthURL, nil)
	require.NoError(t, err)

	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.PostForm = make(url.Values)
	req.Form.Set("grant_type", string(grantType))

	return req
}
