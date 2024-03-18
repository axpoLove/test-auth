package http

import "fmt"

type loginRequest struct {
	GUID string `json:"guid,omitempty"`
}

func (r loginRequest) validate() error {
	if r.GUID == "" {
		return fmt.Errorf("invalid guid")
	}
	return nil
}

type refreshRequest struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (r refreshRequest) validate() error {
	if r.AccessToken == "" {
		return fmt.Errorf("invalid access token")
	}
	if r.RefreshToken == "" {
		return fmt.Errorf("invalid refresh token")
	}
	return nil
}

type errorResponse struct {
	Error string `json:"error,omitempty"`
}
