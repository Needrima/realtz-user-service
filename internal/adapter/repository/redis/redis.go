package repository

import (
	"context"
	"realtz-user-service/internal/core/domain/eto"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"

	"github.com/redis/go-redis/v9"
)

type redisRepo struct {
	client *redis.Client
}

func NewRedisRepo(client *redis.Client) redisRepo {
	return redisRepo{
		client: client,
	}
}

func (r redisRepo) PublishEvent(ctx context.Context, channelName string, data interface{}) error {
	event := eto.NewEvent(data)
	eventJson := event.ToJSON()
	if err := r.client.Publish(ctx, channelName, eventJson).Err(); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not publish event: "+err.Error())
		return errorHelper.NewServiceError("something went wrong", 500)
	}

	return nil
}

func (r redisRepo) SubsribeToEvent(channelName string, handler func(eventJson string)) {
	pubSub := r.client.PSubscribe(context.Background(), channelName)
	defer pubSub.Close()

	ch := pubSub.Channel()
	for msg := range ch {
		logHelper.LogEvent(logHelper.InfoLog, "received data from channle: "+channelName)
		handler(msg.Payload) // Pass the appropriate UserRepository instance here
	}
}
