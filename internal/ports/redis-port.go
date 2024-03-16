package ports

import (
	"context"
)

type RedisPort interface {
	PublishEvent(ctx context.Context, channelName string, data interface{}) error
}
