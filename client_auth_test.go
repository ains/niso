package niso

import (
	"testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/assert"
	"net/http"
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
	req, err := http.NewRequest("POST", testAuthURL + "?client_id=1234&client_secret=aabbccdd", nil)
	require.NoError(t, err)

	auth, err := getClientAuthFromRequest(req, true)
	require.NoError(t, err)

	assert.Equal(t, "1234", auth.Username)
	assert.Equal(t, "aabbccdd", auth.Password)
}

