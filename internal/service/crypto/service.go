package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type service struct {
	accessTokenTTL       time.Duration
	key                  []byte
	refreshTokenLength   int
	refreshTokenHashCost int
}

func (s *service) GenerateAccessToken(guid string) (token string, err error) {
	expiresAt := time.Now().Add(s.accessTokenTTL)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, &UserClaims{
		GUID: guid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	})
	token, err = jwtToken.SignedString(s.key)
	if err != nil {
		err = fmt.Errorf("failed to generate access token: %w", err)
		return
	}
	return
}

func (s *service) ParseAccessToken(token string) (string, error) {
	jwtToken, err := jwt.ParseWithClaims(token, &UserClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.key, nil
	})
	if err != nil {
		return "", err
	}
	claims, ok := jwtToken.Claims.(*UserClaims)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}
	return claims.GUID, nil
}

func (s *service) GenerateRefreshToken() (token string, hashedToken []byte, err error) {
	buf := make([]byte, s.refreshTokenLength)
	_, err = rand.Read(buf)
	if err != nil {
		return
	}
	token = base64.StdEncoding.EncodeToString(buf)
	hashedToken, err = bcrypt.GenerateFromPassword([]byte(token), s.refreshTokenHashCost)
	if err != nil {
		err = fmt.Errorf("failed to hash refresh token: %w", err)
		return
	}
	return
}

func (s *service) CompareRefreshTokens(tokenHash, token string) (err error) {
	err = bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(token))
	return
}

func NewService(
	accessTokenTTL time.Duration,
	key []byte,
	refreshTokenLength int,
	refreshTokenHashCost int,
) *service {
	return &service{
		accessTokenTTL:       accessTokenTTL,
		key:                  key,
		refreshTokenLength:   refreshTokenLength,
		refreshTokenHashCost: refreshTokenHashCost,
	}
}
