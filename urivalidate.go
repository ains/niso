package niso

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// URIValidationError is an error returned when a URI is invalid
// or does not match any URIs provided in the allowed URI list
type URIValidationError string

func (e URIValidationError) Error() string {
	return string(e)
}

func newURIValidationError(msg string, base string, redirect string) URIValidationError {
	return URIValidationError(fmt.Sprintf("%s: %s / %s", msg, base, redirect))
}

// validateURIList validates that redirectURI is contained in baseUriList.
// baseUriList may be a string separated by separator.
// If separator is blank, validate only 1 URI.
func validateURIList(baseURIList string, redirectURI string, separator string) error {
	// make a list of uris
	var slist []string
	if separator != "" {
		slist = strings.Split(baseURIList, separator)
	} else {
		slist = make([]string, 0)
		slist = append(slist, baseURIList)
	}

	for _, sitem := range slist {
		err := validateURI(sitem, redirectURI)
		// validated, return no error
		if err == nil {
			return nil
		}

		// if there was an error that is not a validation error, return it
		if _, iok := err.(URIValidationError); !iok {
			return err
		}
	}

	return newURIValidationError("urls don't validate", baseURIList, redirectURI)
}

// validateURI validates that redirectURI is contained in baseUri
func validateURI(baseURI string, redirectURI string) error {
	if baseURI == "" || redirectURI == "" {
		return errors.New("urls cannot be blank")
	}

	// parse base url
	base, err := url.Parse(baseURI)
	if err != nil {
		return err
	}

	// parse passed url
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return errors.New("url must not include fragment")
	}

	// check if urls match
	if base.Scheme != redirect.Scheme {
		return newURIValidationError("scheme mismatch", baseURI, redirectURI)
	}
	if base.Host != redirect.Host {
		return newURIValidationError("host mismatch", baseURI, redirectURI)
	}

	// allow exact path matches
	if base.Path == redirect.Path {
		return nil
	}

	// ensure prefix matches are actually subpaths
	requiredPrefix := strings.TrimRight(base.Path, "/") + "/"
	if !strings.HasPrefix(redirect.Path, requiredPrefix) {
		return newURIValidationError("path is not a subpath", baseURI, redirectURI)
	}

	// ensure prefix matches don't contain path traversals
	for _, s := range strings.Split(strings.TrimPrefix(redirect.Path, requiredPrefix), "/") {
		if s == ".." {
			return newURIValidationError("subpath cannot contain path traversal", baseURI, redirectURI)
		}
	}

	return nil
}

// firstURI returns the first uri from an uri list
func firstURI(baseURIList string, separator string) string {
	if separator != "" {
		slist := strings.Split(baseURIList, separator)
		if len(slist) > 0 {
			return slist[0]
		}
	} else {
		return baseURIList
	}

	return ""
}
