package main

import (
	"context"
	"net/http"

	"github.com/ains/niso"
	"github.com/ains/niso/example/storage"
)

func main() {
	server := niso.NewServer(niso.NewServerConfig(), storage.NewExampleStorage())

	// Authorization code endpoint
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()
		ar, err := server.GenerateAuthorizeRequest(ctx, r)
		if err != nil {
			niso.WriteErrorResponse(w, err)
			return
		}

		ar.Authorized = true
		resp, err := server.FinishAuthorizeRequest(ctx, ar)
		if err != nil {
			niso.WriteErrorResponse(w, err)
			return
		}

		niso.WriteJSONResponse(w, resp)
	})

	// Access token endpoint
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()
		ar, err := server.GenerateAccessRequest(ctx, r)
		if err != nil {
			niso.WriteErrorResponse(w, err)
			return
		}

		ar.Authorized = true
		resp, err := server.FinishAccessRequest(ctx, ar)
		if err != nil {
			niso.WriteErrorResponse(w, err)
			return
		}

		niso.WriteJSONResponse(w, resp)
	})

	http.ListenAndServe(":14000", nil)
}
