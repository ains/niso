package main

import (
	"context"
	"log"
	"net/http"

	"github.com/ains/niso"
	"github.com/ains/niso/example/storage"
)

func main() {
	server := niso.NewServer(niso.NewServerConfig(), storage.NewExampleStorage())

	// Authorization code endpoint
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()

		resp, err := server.HandleAuthorizeRequest(
			ctx,
			r,
			func(ar *niso.AuthorizationRequest) (bool, error) {
				return true, nil
			},
		)
		if err != nil {
			log.Printf("Error handling authorize request %v", err)
		}

		niso.WriteJSONResponse(w, resp)
	})

	// Access token endpoint
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()

		resp, err := server.HandleAccessRequest(
			ctx,
			r,
			func(ar *niso.AccessRequest) (bool, error) {
				return true, nil
			},
		)
		if err != nil {
			log.Printf("Error handling access request %v", err)
		}

		niso.WriteJSONResponse(w, resp)
	})

	http.ListenAndServe(":14000", nil)
}
