package niso

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientAuthFromRequestHeader(t *testing.T) {
	req, err := http.NewRequest("POST", testAuthURL, nil)
	require.NoError(t, err)

	req.SetBasicAuth("1234", "aabbccdd")
	auth, err := getClientAuthFromRequest(req, false)
	require.NoError(t, err)

	assert.Equal(t, "1234", auth.Username)
	assert.Equal(t, "aabbccdd", auth.Password)
}

func TestClientAuthFromRequestQueryParams(t *testing.T) {
	req, err := http.NewRequest("POST", testAuthURL+"?client_id=1234&client_secret=aabbccdd", nil)
	require.NoError(t, err)

	auth, err := getClientAuthFromRequest(req, true)
	require.NoError(t, err)

	assert.Equal(t, "1234", auth.Username)
	assert.Equal(t, "aabbccdd", auth.Password)
}

func TestClientAuthFromRequestBasicAuthFirst(t *testing.T) {
	req, err := http.NewRequest("POST", testAuthURL+"?client_id=ignore_this&client_secret=ignore_that", nil)
	require.NoError(t, err)

	req.SetBasicAuth("1234", "aabbccdd")
	auth, err := getClientAuthFromRequest(req, true)
	require.NoError(t, err)

	assert.Equal(t, "1234", auth.Username)
	assert.Equal(t, "aabbccdd", auth.Password)
}

func TestClientAuthFromRequestTotalFail(t *testing.T) {
	req, err := http.NewRequest("POST", testAuthURL, nil)
	require.NoError(t, err)

	_, err = getClientAuthFromRequest(req, false)
	assert.Error(t, err, "invalid authorization header")
}