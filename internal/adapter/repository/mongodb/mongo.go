package repository

import (
	"context"
	"fmt"
	"realtz-user-service/internal/core/domain/entity"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"

	"go.mongodb.org/mongo-driver/bson"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type mongoRepo struct {
	collection *mongo.Collection
}

func NewMongoRepo(collection *mongo.Collection) mongoRepo {
	return mongoRepo{
		collection: collection,
	}
}

func (m mongoRepo) CreateUser(ctx context.Context, user entity.User) (interface{}, error) {

	if _, err := m.GetUserByEmail(ctx, user.Email); err == nil {
		return nil, errorHelper.NewServiceError("email has been taken", 409)
	}

	if _, err := m.GetUserByPhoneNumber(ctx, user.PhoneNumber); err == nil {
		return nil, errorHelper.NewServiceError("phone number has been taken", 409)
	}

	if _, err := m.GetUserByUsername(ctx, user.Username); err == nil {
		return nil, errorHelper.NewServiceError("username has been taken", 409)
	}

	_, err := m.collection.InsertOne(ctx, user)
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not store new user in db: "+err.Error())
		return nil, errorHelper.NewServiceError("something went wrong", 500)
	}

	logHelper.LogEvent(logHelper.SuccessLog, fmt.Sprintf("successfully created user. Firstname: %s, Lastname: %s", user.Firstname, user.Lastname))

	return "user created successfully", nil
}

func (m mongoRepo) GetUserByEmail(ctx context.Context, email string) (interface{}, error) {
	user := entity.User{}
	filter := bson.M{"email": bson.M{"$regex": fmt.Sprintf("^%s$", email), "$options": "i"}}
	if err := m.collection.FindOne(ctx, filter).Decode(&user); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, fmt.Sprintf("cannot find user with email: %s, error: %s", email, err.Error()))
		return nil, errorHelper.NewServiceError("user not found", 404)
	}

	logHelper.LogEvent(logHelper.SuccessLog, fmt.Sprintf("successfully retrieved user with email: %s", email))

	return user, nil
}

func (m mongoRepo) GetUserByReference(ctx context.Context, reference string) (interface{}, error) {
	user := entity.User{}
	if err := m.collection.FindOne(ctx, bson.M{"reference": reference}).Decode(&user); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, fmt.Sprintf("cannot find user with reference: %s, error: %s", reference, err.Error()))
		return nil, errorHelper.NewServiceError("user not found", 404)
	}

	logHelper.LogEvent(logHelper.SuccessLog, fmt.Sprintf("successfully retrieved user with reference: %s", reference))

	return user, nil
}

func (m mongoRepo) GetUserByUsername(ctx context.Context, username string) (interface{}, error) {
	user := entity.User{}
	filter := bson.M{"username": bson.M{"$regex": fmt.Sprintf("^%s$", username), "$options": "i"}}
	if err := m.collection.FindOne(ctx, filter).Decode(&user); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, fmt.Sprintf("cannot find user with username: %s, error: %s", username, err.Error()))
		return nil, errorHelper.NewServiceError("user not found", 404)
	}

	logHelper.LogEvent(logHelper.SuccessLog, fmt.Sprintf("successfully retrieved user with username: %s", username))

	return user, nil
}

func (m mongoRepo) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (interface{}, error) {
	user := entity.User{}
	if err := m.collection.FindOne(ctx, bson.M{"phone_number": phoneNumber}).Decode(&user); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "cannot find user with email: "+err.Error())
		return nil, errorHelper.NewServiceError("user not found", 404)
	}

	logHelper.LogEvent(logHelper.SuccessLog, fmt.Sprintf("successfully retrieved user with phone number: %s", phoneNumber))

	return user, nil
}

func (m mongoRepo) UpdateUser(ctx context.Context, updateUser entity.User) (interface{}, error) {
	if _, err := m.collection.UpdateOne(ctx, bson.M{"reference": updateUser.Reference}, bson.M{"$set": updateUser}); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not update user: "+err.Error())
		return nil, errorHelper.NewServiceError("something went wrong. try again", 500)
	}

	logHelper.LogEvent(logHelper.SuccessLog, fmt.Sprintf("successfully updated user firstname: %s, lastname: %s", updateUser.Firstname, updateUser.Lastname))

	return "user updated successfully", nil
}
