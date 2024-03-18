package models

import "time"

type RefreshToken struct {
	GUID      string    `bson:"guid"`
	Hash      string    `bson:"hash"`
	ExpiresAt time.Time `bson:"expiresAt"`
}
