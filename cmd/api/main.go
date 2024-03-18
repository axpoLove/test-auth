package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"test-auth/internal/config"
	"test-auth/internal/repository"
	"test-auth/internal/service/auth"
	"test-auth/internal/service/crypto"
	httptransport "test-auth/internal/transport/http"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.NewConfig()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		return
	}

	client, err := mongo.Connect(
		ctx,
		options.Client().ApplyURI(cfg.Mongo.URI()),
	)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return
	}
	defer func() {
		errDisconnect := client.Disconnect(ctx)
		if errDisconnect != nil {
			logger.Error("failed to close database client", "error", errDisconnect)
		}
	}()

	if err = client.Ping(ctx, nil); err != nil {
		logger.Error("failed to ping database", "error", err)
		return
	}

	repo := repository.NewRepository(
		client,
		cfg.Mongo.Database,
		cfg.Mongo.RefreshTokenCollection,
	)

	cryptoService := crypto.NewService(
		cfg.Auth.AccessTokenTTL,
		[]byte(cfg.Auth.SecretKey),
		cfg.Auth.RefreshTokenLength,
		bcrypt.DefaultCost,
	)

	authService := auth.NewService(
		repo,
		cryptoService,
		cfg.Auth.RefreshTokenTTL,
	)

	server := httptransport.NewServer(cfg.Server.Port, cfg.Server.ReadHeaderTimeout, authService, logger)
	serverErrors := make(chan error)
	go func() {
		err := server.Start()
		if err != nil {
			serverErrors <- err
		}
	}()
	logger.Info("server started")

	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		logger.Error("server failed", "error", err)
		return
	}
	logger.Info("server stopped")
}
