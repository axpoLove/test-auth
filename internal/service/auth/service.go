package auth

import (
	"context"
	"fmt"
	"time"

	"test-auth/internal/models"
)

type cryptoService interface {
	GenerateAccessToken(guid string) (token string, err error)
	GenerateRefreshToken() (token string, hashedToken []byte, err error)
	ParseAccessToken(token string) (string, error)
	CompareRefreshTokens(tokenHash, token string) error
}

type repository interface {
	SaveRefreshToken(ctx context.Context, guid, token string, ttl time.Duration) error
	GetRefreshToken(ctx context.Context, guid string) (token models.RefreshToken, err error)
}

type service struct {
	repository      repository
	cryptoService   cryptoService
	refreshTokenTTL time.Duration
}

func (s *service) Login(ctx context.Context, guid string) (accessToken, refreshToken string, err error) {
	accessToken, err = s.cryptoService.GenerateAccessToken(guid)
	if err != nil {
		err = fmt.Errorf("failed to generate access token: %w", err)
		return
	}
	var refreshTokenHash []byte
	refreshToken, refreshTokenHash, err = s.cryptoService.GenerateRefreshToken()
	if err != nil {
		err = fmt.Errorf("failed to generate refresh token: %w", err)
		return
	}
	err = s.repository.SaveRefreshToken(ctx, guid, string(refreshTokenHash), s.refreshTokenTTL)
	if err != nil {
		err = fmt.Errorf("failed to save refresh token: %w", err)
		return
	}
	return accessToken, refreshToken, nil
}

func (s *service) Refresh(
	ctx context.Context,
	accessToken string,
	refreshToken string,
) (
	newAccessToken string,
	newRefreshToken string,
	err error,
) {
	guid, err := s.cryptoService.ParseAccessToken(accessToken)
	if err != nil {
		return newAccessToken, newRefreshToken, fmt.Errorf("failed to parse access token: %w", err)
	}
	var previousRefreshToken models.RefreshToken
	previousRefreshToken, err = s.repository.GetRefreshToken(ctx, guid)
	if err != nil {
		return newAccessToken, newRefreshToken, fmt.Errorf("failed to get refresh token: %w", err)
	}
	if previousRefreshToken.GUID == "" {
		return newAccessToken, newRefreshToken, fmt.Errorf("refresh token doesn't exist")
	}
	if previousRefreshToken.ExpiresAt.Before(time.Now().UTC()) {
		return newAccessToken, newRefreshToken, fmt.Errorf("refresh token is expired")
	}
	err = s.cryptoService.CompareRefreshTokens(previousRefreshToken.Hash, refreshToken)
	if err != nil {
		return newAccessToken, newRefreshToken, fmt.Errorf("invalid token: %w", err)
	}
	return s.Login(ctx, guid)
}

func NewService(
	repository repository,
	cryptoService cryptoService,
	refreshTokenTTL time.Duration,
) *service {
	return &service{
		repository:      repository,
		cryptoService:   cryptoService,
		refreshTokenTTL: refreshTokenTTL,
	}
}
