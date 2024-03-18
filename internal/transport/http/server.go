package http

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type authService interface {
	Login(ctx context.Context, guid string) (accessToken, refreshToken string, err error)
	Refresh(
		ctx context.Context,
		accessToken string,
		refreshToken string,
	) (
		newAccessToken string,
		newRefreshToken string,
		err error,
	)
}

type server struct {
	srv         *http.Server
	port        int
	router      *chi.Mux
	authService authService
	logger      *slog.Logger
}

func (s *server) Start() error {
	return s.srv.ListenAndServe()
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		s.apiError(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = request.validate()
	if err != nil {
		s.apiError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var accessToken, refreshToken string
	accessToken, refreshToken, err = s.authService.Login(r.Context(), request.GUID)
	if err != nil {
		s.apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.NewEncoder(w).Encode(&loginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	if err != nil {
		s.logger.Error("failed to write response", "error", err)
	}
}

func (s *server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var request refreshRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		s.apiError(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = request.validate()
	if err != nil {
		s.apiError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var newAccessToken, newRefreshToken string
	newAccessToken, newRefreshToken, err = s.authService.Refresh(
		r.Context(),
		request.AccessToken,
		request.RefreshToken,
	)
	if err != nil {
		s.apiError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.NewEncoder(w).Encode(&loginResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	})
	if err != nil {
		s.logger.Error("failed to write response", "error", err)
	}
}

func (s *server) apiError(w http.ResponseWriter, msg string, status int) {
	s.logger.Error("unexpected error", "error", msg)
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(&errorResponse{Error: msg})
	if err != nil {
		s.logger.Error("failed to encode response error", "errot", err)
	}
}

func NewServer(
	port int,
	readHeaderTimeout time.Duration,
	authService authService,
	logger *slog.Logger,
) *server {
	router := chi.NewRouter()
	s := &server{
		port:        port,
		router:      router,
		authService: authService,
		logger:      logger,
	}
	router.Use(middleware.Logger)
	router.Post("/login", s.handleAuth)
	router.Post("/refresh", s.handleRefresh)

	srv := http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(port)),
		Handler:           router,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	s.srv = &srv
	return s
}
