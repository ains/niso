package niso

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ResponseData is the data to be serialized for response output
type ResponseData map[string]interface{}

// ResponseType enum indicates type of response
type ResponseType int

// Responses can either be data (an have a body to to be serialized) or are a redirect.
const (
	DATA ResponseType = iota
	REDIRECT
)

// Response represents a HTTP response to be sent to the user
type Response struct {
	StatusCode int
	Data       ResponseData
	Headers    http.Header

	responseType       ResponseType
	redirectURL        string
	redirectInFragment bool
}

// NewResponse creates a new empty response
func NewResponse() *Response {
	r := &Response{
		responseType: DATA,
		StatusCode:   200,
		Data:         make(ResponseData),
		Headers:      make(http.Header),
	}
	r.Headers.Add(
		"Cache-Control",
		"no-cache, no-store, max-age=0, must-revalidate",
	)
	r.Headers.Add("Pragma", "no-cache")
	r.Headers.Add("Expires", "Fri, 01 Jan 1990 00:00:00 GMT")
	return r
}

func newInternalServerErrorResponse(message string) *Response {
	r := &Response{
		responseType: DATA,
		StatusCode:   http.StatusInternalServerError,
		Data: map[string]interface{}{
			"message": message,
		},
		Headers: make(http.Header),
	}

	return r
}

// SetRedirectURL changes the response to redirect to the given url
func (r *Response) SetRedirectURL(url string) {
	// set redirect parameters
	r.responseType = REDIRECT
	r.redirectURL = url
}

// SetRedirectFragment sets redirect values to be passed in fragment instead of as query parameters
func (r *Response) SetRedirectFragment(f bool) {
	r.redirectInFragment = f
}

// GetRedirectURL returns the redirect url with all query string parameters
func (r *Response) GetRedirectURL() (string, error) {
	if r.responseType != REDIRECT {
		return "", errors.New("Not a redirect response")
	}

	u, err := url.Parse(r.redirectURL)
	if err != nil {
		return "", err
	}

	var q url.Values
	if r.redirectInFragment {
		// start with empty set for fragment
		q = url.Values{}
	} else {
		// add parameters to existing query
		q = u.Query()
	}

	// add parameters
	for n, v := range r.Data {
		q.Set(n, fmt.Sprint(v))
	}

	// https://tools.ietf.org/html/rfc6749#section-4.2.2
	// Fragment should be encoded as application/x-www-form-urlencoded (%-escaped, spaces are represented as '+')
	// The stdlib redirectURL#String() doesn't make that easy to accomplish, so build this ourselves
	if r.redirectInFragment {
		u.Fragment = ""
		redirectURI := u.String() + "#" + q.Encode()
		return redirectURI, nil
	}

	// Otherwise, update the query and encode normally
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}
