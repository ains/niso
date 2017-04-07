package niso

import (
	"time"
)

// Server is an OAuth2 implementation
type Server struct {
	Config                  *ServerConfig
	Storage                 Storage
	AuthorizeTokenGenerator AuthorizeTokenGenerator
	AccessTokenGenerator    AccessTokenGenerator
	AccessTokenSubScoper    AccessTokenSubScoper
	Now                     func() time.Time
}

// NewServer creates a new server instance
func NewServer(config *ServerConfig, storage Storage) *Server {
	return &Server{
		Config:                  config,
		Storage:                 storage,
		AuthorizeTokenGenerator: &DefaultAuthorizeTokenGenerator{},
		AccessTokenGenerator:    &DefaultAccessTokenGenerator{},
		AccessTokenSubScoper:    &DefaultAccessTokenSubScoper{},
		Now:                     time.Now,
	}
}
