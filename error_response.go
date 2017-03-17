package niso

import "net/http"

// WriteErrorResponse redirects the user or encodes the error to JSON and writes to the http.ResponseWriter
func WriteErrorResponse(w http.ResponseWriter, error error) error {
	var nisoErr *NisoError
	if ne, ok := error.(*NisoError); ok {
		nisoErr = ne
	} else {
		nisoErr = NewWrappedNisoError(E_SERVER_ERROR, error, "unknown error")
	}

	// Redirect user if needed
	loc, err := nisoErr.GetRedirectURI()
	if err != nil {
		return err
	}
	if loc != "" {
		w.Header().Add("Location", loc)
		w.WriteHeader(302)
	}

	// No redirect output error as a JSON response
	resp := NewResponse()
	resp.StatusCode = statusCodeForError(nisoErr)
	for k, v := range nisoErr.GetResponseDict() {
		if v != "" {
			resp.Data[k] = v
		}
	}

	return WriteJSONResponse(w, resp)
}

// status code to return for a given error code as per (https://tools.ietf.org/html/rfc6749#section-5.2)
func statusCodeForError(error *NisoError) int {
	if error.Code == E_SERVER_ERROR {
		return 500
	} else if error.Code == E_TEMPORARILY_UNAVAILABLE {
		return 503
	} else if error.Code == E_INVALID_CLIENT || error.Code == E_ACCESS_DENIED {
		return 401
	}

	return 400
}
