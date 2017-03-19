package storage

import (
	"context"
	"errors"

	"github.com/ains/niso"
)

type ExampleStorage struct {
	clients   map[string]*niso.ClientData
	authorize map[string]*niso.AuthorizeData
	access    map[string]*niso.AccessData
	refresh   map[string]*niso.RefreshTokenData
}

func NewExampleStorage() *ExampleStorage {
	r := &ExampleStorage{
		clients:   make(map[string]*niso.ClientData),
		authorize: make(map[string]*niso.AuthorizeData),
		access:    make(map[string]*niso.AccessData),
		refresh:   make(map[string]*niso.RefreshTokenData),
	}

	r.clients["1234"] = &niso.ClientData{
		ClientID:     "1234",
		ClientSecret: "aabbccdd",
		RedirectURI:  "http://localhost:14000/appauth",
	}

	return r
}

func (s *ExampleStorage) Close() error {
	return nil
}

func (s *ExampleStorage) GetClientData(_ context.Context, id string) (*niso.ClientData, error) {
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, &niso.NotFoundError{Err: errors.New("client not found")}
}

func (s *ExampleStorage) SetClient(id string, client *niso.ClientData) error {
	s.clients[id] = client
	return nil
}

func (s *ExampleStorage) SaveAuthorizeData(_ context.Context, data *niso.AuthorizeData) error {
	s.authorize[data.Code] = data
	return nil
}

func (s *ExampleStorage) GetAuthorizeData(_ context.Context, code string) (*niso.AuthorizeData, error) {
	if d, ok := s.authorize[code]; ok {
		return d, nil
	}
	return nil, errors.New("authorize not found")
}

func (s *ExampleStorage) DeleteAuthorizeData(ctx context.Context, code string) error {
	delete(s.authorize, code)
	return nil
}

func (s *ExampleStorage) SaveAccessData(ctx context.Context, data *niso.AccessData) error {
	s.access[data.AccessToken] = data
	return nil
}

func (s *ExampleStorage) GetRefreshTokenData(ctx context.Context, token string) (*niso.RefreshTokenData, error) {
	if d, ok := s.refresh[token]; ok {
		return d, nil
	}
	return nil, errors.New("refresh token data not found")
}

func (s *ExampleStorage) SaveRefreshTokenData(ctx context.Context, data *niso.RefreshTokenData) error {
	s.refresh[data.RefreshToken] = data
	return nil
}

func (s *ExampleStorage) DeleteRefreshTokenData(ctx context.Context, token string) error {
	delete(s.refresh, token)
	return nil
}

func (s *ExampleStorage) RemoveAccess(code string) error {
	delete(s.access, code)
	return nil
}
