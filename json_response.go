package niso

import (
	"encoding/json"
	"net/http"
)

// WriteJSONResponse encodes the Response to JSON and writes to the http.ResponseWriter
func WriteJSONResponse(w http.ResponseWriter, r *Response) error {
	for i, k := range r.Headers {
		for _, v := range k {
			w.Header().Add(i, v)
		}
	}

	if r.responseType == REDIRECT {
		// Output redirect with parameters
		u, err := r.GetRedirectURL()
		if err != nil {
			return err
		}
		w.Header().Add("Location", u)
		w.WriteHeader(302)
	} else {
		// set content type if the response doesn't already have one associated with it
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(r.StatusCode)

		encoder := json.NewEncoder(w)
		err := encoder.Encode(r.Data)
		if err != nil {
			return err
		}
	}
	return nil
}
