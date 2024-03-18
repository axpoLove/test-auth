package repository

import (
	"context"
	"errors"
	"time"

	"test-auth/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type repository struct {
	cli                    *mongo.Client
	databaseName           string
	refreshTokenCollection string
}

func (r *repository) SaveRefreshToken(ctx context.Context, guid, tokenHash string, ttl time.Duration) (err error) {
	collection := r.cli.Database(r.databaseName).Collection(r.refreshTokenCollection)
	opts := options.Update().SetUpsert(true)
	_, err = collection.UpdateOne(
		ctx,
		bson.M{"guid": guid},
		bson.M{"$set": bson.M{
			"hash":      tokenHash,
			"expiresAt": time.Now().UTC().Add(ttl),
		}},
		opts,
	)
	return
}

func (r *repository) GetRefreshToken(ctx context.Context, guid string) (token models.RefreshToken, err error) {
	collection := r.cli.Database(r.databaseName).Collection(r.refreshTokenCollection)

	err = collection.FindOne(ctx, bson.M{"guid": guid}).Decode(&token)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		return
	}
	return token, nil
}

func NewRepository(
	cli *mongo.Client,
	databaseName string,
	refreshTokenCollection string,
) *repository {
	return &repository{
		cli:                    cli,
		databaseName:           databaseName,
		refreshTokenCollection: refreshTokenCollection,
	}
}
