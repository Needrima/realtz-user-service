package ports

import (
	"context"
	"realtz-user-service/internal/core/domain/entity"
)

type MongoDBPort interface {
	CreateUser(ctx context.Context, user entity.User) (interface{}, error)
	GetUserByEmail(ctx context.Context, email string) (interface{}, error)
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (interface{}, error)
	GetUserByReference(ctx context.Context, reference string) (interface{}, error)
	GetUserByUsername(ctx context.Context, username string) (interface{}, error)
	UpdateUser(ctx context.Context, updateUser entity.User) (interface{}, error)
	DeleteAccount(ctx context.Context, currentUser entity.User) (interface{}, error)
}
