package repository

import (
	"context"
	"os"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func ConnectToMongoDB() mongoRepo {
	logHelper.LogEvent(logHelper.InfoLog, "Establishing Redis connection")
	clientOptions := options.Client().ApplyURI(configHelper.ServiceConfiguration.MongoDBConnString)
	ctx, cancle := context.WithTimeout(context.Background(), time.Second*20)
	defer cancle()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		logHelper.LogEvent(logHelper.DangerLog, "could not connect to mongoDB: "+err.Error())
		os.Exit(1)
	}

	if err := client.Ping(context.Background(), readpref.Primary()); err != nil {
		logHelper.LogEvent(logHelper.DangerLog, "pinging mongo DB: "+err.Error())
		os.Exit(1)
	}

	collection := client.Database(configHelper.ServiceConfiguration.MongoDbDatabaseName).
		Collection(configHelper.ServiceConfiguration.MongoDBUserCollectionName)

	return NewMongoRepo(collection)
}
