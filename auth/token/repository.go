package token

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"

	"auth/db"
)

func NewTokenRepository(authDb *db.AuthDB) *TokenRepository {
	return &TokenRepository{
		collection: authDb.Database.Collection("token"),
	}
}

type TokenRepository struct {
	collection *mongo.Collection
}

func (ar *TokenRepository) Save(t *Token) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ar.collection.InsertOne(ctx, t)
	if err != nil {
		log.Println("データベース保存エラー")
		return err
	}
	return nil
}
