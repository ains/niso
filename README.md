# NISO
An improved Golang OAuth2 server library

[![Go Report Card](https://goreportcard.com/badge/github.com/ains/niso)](https://goreportcard.com/report/github.com/ains/niso) [![Build Status](https://travis-ci.org/ains/niso.svg?branch=master)](https://travis-ci.org/ains/niso) [![GoDoc](https://godoc.org/github.com/ains/niso?status.svg)](https://godoc.org/github.com/ains/niso)

## Introduction

NISO is an OAuth2 server library for the Go language, forked from [OSIN](https://github.com/RangelReale/osin).
The project can be used build your own OAuth2 authentication service as per the speficiation at [http://tools.ietf.org/html/rfc6749](http://tools.ietf.org/html/rfc6749).

This fork offers the following advantages over OSIN:
* Cleaner, simpler, majorly side-effect free API
* Improved error messages and propagated error context using [pkg/errors](https://github.com/pkg/errors)
* [Context](https://golang.org/pkg/context/) support
* Improved test coverage

## Example Server

````go
server := niso.NewServer(niso.NewServerConfig(), storage.NewExampleStorage())

// Authorization code endpoint
http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
    resp, err := server.HandleHTTPAuthorizeRequest(
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
    resp, err := server.HandleHTTPAccessRequest(
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
````

## Example Access

Open in your web browser:

````
http://localhost:14000/authorize?response_type=code&client_id=1234&redirect_uri=http%3A%2F%2Flocalhost%3A14000%2Fappauth%2Fcode
````
