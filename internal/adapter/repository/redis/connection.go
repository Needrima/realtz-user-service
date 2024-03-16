package repository

import (
	"context"
	"encoding/json"
	"os"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	"time"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

func ConnectToRedis() redisRepo {
	logHelper.LogEvent(logHelper.InfoLog, "Establishing Redis connection")
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     configHelper.ServiceConfiguration.RedisConnString,
		DB:       0,
		Password: "",
	})

	// Create a context with a timeout (adjust the timeout as needed)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Send a PING command to Redis to check the connection
	_, err := RedisClient.Ping(ctx).Result()
	if err != nil {
		logHelper.LogEvent(logHelper.DangerLog, "could not connect to redis: "+err.Error())
		os.Exit(1)
	}

	// initialize revoked tokens key in redis
	revokedTokens := make([]string, 0)

	intialRevokedTokensJson, err := json.Marshal(revokedTokens)
	if err != nil {
		logHelper.LogEvent(logHelper.DangerLog, "initializing revoked tokens key in redis: "+err.Error())
		os.Exit(1)
	}

	if err := RedisClient.Set(context.Background(), configHelper.ServiceConfiguration.RedisRevokedTokensKey, string(intialRevokedTokensJson), 0).Err(); err != nil {
		logHelper.LogEvent(logHelper.DangerLog, "setting revoked tokens key in redis: "+err.Error())
		os.Exit(1)
	}

	return NewRedisRepo(RedisClient)
}
