package niso

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestAccessAuthorizationCode(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGenerator = &TestingAccessTokenGen{}

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	ctx := context.TODO()
	ar, err := server.HandleAccessRequest(ctx, req)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ar.Authorized = true
	resp, err := server.FinishAccessRequest(ctx, ar)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Data["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Data["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessRefreshToken(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGenerator = &TestingAccessTokenGen{}

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "r9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	ctx := context.TODO()
	ar, err := server.HandleAccessRequest(ctx, req)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ar.Authorized = true
	resp, err := server.FinishAccessRequest(ctx, ar)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Data["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Data["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessPassword(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{PASSWORD}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGenerator = &TestingAccessTokenGen{}

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(PASSWORD))
	req.Form.Set("username", "testing")
	req.Form.Set("password", "testing")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	ctx := context.TODO()
	ar, err := server.HandleAccessRequest(ctx, req)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ar.Authorized = ar.Username == "testing" && ar.Password == "testing"
	resp, err := server.FinishAccessRequest(ctx, ar)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Data["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Data["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessClientCredentials(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGenerator = &TestingAccessTokenGen{}

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	ctx := context.TODO()
	ar, err := server.HandleAccessRequest(ctx, req)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ar.Authorized = true
	resp, err := server.FinishAccessRequest(ctx, ar)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Data["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d, dok := resp.Data["refresh_token"]; dok {
		t.Fatalf("Refresh token should not be generated: %s", d)
	}
}

func TestExtraScopes(t *testing.T) {
	if extraScopes("", "") == true {
		t.Fatalf("extraScopes returned true with empty scopes")
	}

	if extraScopes("a", "") == true {
		t.Fatalf("extraScopes returned true with less scopes")
	}

	if extraScopes("a,b", "b,a") == true {
		t.Fatalf("extraScopes returned true with matching scopes")
	}

	if extraScopes("a,b", "b,a,c") == false {
		t.Fatalf("extraScopes returned false with extra scopes")
	}

	if extraScopes("", "a") == false {
		t.Fatalf("extraScopes returned false with extra scopes")
	}

}

func TestAccessAuthorizationCodePKCE(t *testing.T) {
	testcases := map[string]struct {
		Challenge       string
		ChallengeMethod string
		Verifier        string
		ExpectedError   string
	}{
		"good, plain": {
			Challenge: "12345678901234567890123456789012345678901234567890",
			Verifier:  "12345678901234567890123456789012345678901234567890",
		},
		"bad, plain": {
			Challenge:     "12345678901234567890123456789012345678901234567890",
			Verifier:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError: "invalid_grant",
		},
		"good, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: "S256",
			Verifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		"bad, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: "S256",
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError:   "invalid_grant",
		},
		"missing from storage": {
			Challenge:       "",
			ChallengeMethod: "",
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
	}
	ctx := context.TODO()

	for k, test := range testcases {
		testStorage := NewTestingStorage()
		sconfig := NewServerConfig()
		sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
		server := NewServer(sconfig, testStorage)
		server.AccessTokenGenerator = &TestingAccessTokenGen{}
		server.Storage.SaveAuthorizeData(ctx, &AuthorizeData{
			ClientData:          testStorage.clients["public-client"],
			Code:                "pkce-code",
			ExpiresIn:           3600,
			CreatedAt:           time.Now(),
			RedirectUri:         "http://localhost:14000/appauth",
			CodeChallenge:       test.Challenge,
			CodeChallengeMethod: test.ChallengeMethod,
		})

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth("public-client", "")

		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
		req.Form.Set("code", "pkce-code")
		req.Form.Set("state", "a")
		req.Form.Set("code_verifier", test.Verifier)
		req.PostForm = make(url.Values)

		ar, err := server.HandleAccessRequest(ctx, req)
		if err != nil {
			if e, ok := err.(*NisoError); ok {
				if test.ExpectedError != string(e.ErrorCode) {
					t.Errorf("%s: unexpected error: %v, %v", k, e.ErrorCode, err.Error())
					continue
				}
			} else {
				t.Error("Expected niso error, got: ", err.Error())
			}
		} else {
			ar.Authorized = true
			resp, err := server.FinishAccessRequest(ctx, ar)
			if err != nil {
				t.Fatalf(err.Error())
			}

			if test.ExpectedError == "" {
				if resp.Type != DATA {
					t.Fatalf("%s: Response should be data", k)
				}
				if d := resp.Data["access_token"]; d != "1" {
					t.Fatalf("%s: Unexpected access token: %s", k, d)
				}
				if d := resp.Data["refresh_token"]; d != "r1" {
					t.Fatalf("%s: Unexpected refresh token: %s", k, d)
				}
			}
		}
	}
}
