package niso

import (
	"context"
	"errors"
	"strconv"
	"time"
)

type TestingStorage struct {
	clients   map[string]*ClientData
	authorize map[string]*AuthorizeData
	access    map[string]*AccessData
	refresh   map[string]*RefreshTokenData
}

func NewTestingStorage() *TestingStorage {
	r := &TestingStorage{
		clients:   make(map[string]*ClientData),
		authorize: make(map[string]*AuthorizeData),
		access:    make(map[string]*AccessData),
		refresh:   make(map[string]*RefreshTokenData),
	}

	r.clients["1234"] = &ClientData{
		ClientID:     "1234",
		ClientSecret: "aabbccdd",
		RedirectURI:  "http://localhost:14000/appauth",
	}

	r.clients["public-client"] = &ClientData{
		ClientID:    "public-client",
		RedirectURI: "http://localhost:14000/appauth",
	}

	r.authorize["9999"] = &AuthorizeData{
		ClientData:  r.clients["1234"],
		Code:        "9999",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectURI: "http://localhost:14000/appauth",
	}

	r.access["9999"] = &AccessData{
		ClientData:  r.clients["1234"],
		AccessToken: "9999",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
	}

	r.refresh["r9999"] = &RefreshTokenData{
		ClientID:     "1234",
		RefreshToken: "9999",
	}

	return r
}

func (s *TestingStorage) Close() error {
	return nil
}

func (s *TestingStorage) GetClientData(_ context.Context, id string) (*ClientData, error) {
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, &NotFoundError{Err: errors.New("client not found")}
}

func (s *TestingStorage) SetClient(id string, client *ClientData) error {
	s.clients[id] = client
	return nil
}

func (s *TestingStorage) SaveAuthorizeData(_ context.Context, data *AuthorizeData) error {
	s.authorize[data.Code] = data
	return nil
}

func (s *TestingStorage) GetAuthorizeData(_ context.Context, code string) (*AuthorizeData, error) {
	if d, ok := s.authorize[code]; ok {
		return d, nil
	}
	return nil, errors.New("authorize not found")
}

func (s *TestingStorage) DeleteAuthorizeData(ctx context.Context, code string) error {
	delete(s.authorize, code)
	return nil
}

func (s *TestingStorage) SaveAccessData(ctx context.Context, data *AccessData) error {
	s.access[data.AccessToken] = data
	return nil
}

func (s *TestingStorage) GetRefreshTokenData(ctx context.Context, token string) (*RefreshTokenData, error) {
	if d, ok := s.refresh[token]; ok {
		return d, nil
	}
	return nil, errors.New("refresh token data not found")
}

func (s *TestingStorage) SaveRefreshTokenData(ctx context.Context, data *RefreshTokenData) error {
	s.refresh[data.RefreshToken] = data
	return nil
}

func (s *TestingStorage) DeleteRefreshTokenData(ctx context.Context, token string) error {
	delete(s.refresh, token)
	return nil
}

func (s *TestingStorage) RemoveAccess(code string) error {
	delete(s.access, code)
	return nil
}

// Predictable testing token generation

type TestingAuthorizeTokenGen struct {
	counter int64
}

func (a *TestingAuthorizeTokenGen) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	a.counter++
	return strconv.FormatInt(a.counter, 10), nil
}

type TestingAccessTokenGen struct {
	acounter int64
	rcounter int64
}

func (a *TestingAccessTokenGen) GenerateAccessToken(data *AccessRequest) (string, error) {
	a.acounter++
	return strconv.FormatInt(a.acounter, 10), nil
}

func (a *TestingAccessTokenGen) GenerateRefreshToken(data *AccessRequest) (string, error) {
	a.rcounter++
	return "r" + strconv.FormatInt(a.rcounter, 10), nil
}
