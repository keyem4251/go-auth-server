package main

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewDB() *MongoDB {
	client, err := connectMongoDB()
	if err != nil {
		log.Fatal("MongoDB接続エラー")
	}
	log.Println("MongoDBに接続")
	database := client.Database("auth")
	return &MongoDB{
		Database: database,
	}
}

type MongoDB struct {
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
