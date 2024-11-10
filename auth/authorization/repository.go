package authorization

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"auth/db"
)

type AuthorizationRepository struct {
	collection *mongo.Collection
}

func NewAuthorizationRepository(authDb *db.AuthDB) *AuthorizationRepository {
	return &AuthorizationRepository{
		collection: authDb.Database.Collection("authorization"),
	}
}

func (ar *AuthorizationRepository) Save(ac *AuthorizationCode) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ar.collection.InsertOne(ctx, ac)
	if err != nil {
		log.Println("データベース保存エラー")
		return err
	}
	return nil
}

func (ar *AuthorizationRepository) FindOne(clientId string) (*AuthorizationCode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var authorizationCode AuthorizationCode
	err := ar.collection.FindOne(ctx, bson.D{{Key: "clientid", Value: clientId}}).Decode(&authorizationCode)
	if err != nil {
		log.Println("データベース検索エラー")
		return nil, err
	}
	return &authorizationCode, nil
}
