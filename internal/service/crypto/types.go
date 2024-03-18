package crypto

import "github.com/golang-jwt/jwt/v5"

type UserClaims struct {
	GUID string `json:"guid"`
	jwt.RegisteredClaims
}
