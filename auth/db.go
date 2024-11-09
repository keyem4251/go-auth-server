package main

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewAuthDB() *AuthDB {
	client, err := connectMongoDB()
	if err != nil {
		log.Fatal("MongoDB接続エラー")
	}
	log.Println("MongoDBに接続")
	database := client.Database("auth")
	return &AuthDB{
		Database: database,
	}
}

type AuthDB struct {
	Database *mongo.Database
}

func connectMongoDB() (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	clientOptions := options.Client().ApplyURI(dbHost + ":" + dbPort)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("MongoDB接続エラー: %v\n", err)
		return nil, err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("MongoDB接続に失敗しました: %v", err)
		return nil, err
	}

	return client, nil
}

type AuthorizationRepository struct {
	collection *mongo.Collection
}

func NewAuthorizationRepository(authDb *AuthDB) *AuthorizationRepository {
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

func NewTokenRepository(authDb *AuthDB) *TokenRepository {
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
