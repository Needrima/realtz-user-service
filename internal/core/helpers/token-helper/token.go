package helper

import (
	"context"
	"encoding/json"
	redisRepo "realtz-user-service/internal/adapter/repository/redis"
	"realtz-user-service/internal/core/domain/entity"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	"time"

	"github.com/golang-jwt/jwt"
)

// RevokeToken add a token to the revoked tokens map
func RevokeToken(token string) error {
	ctx, cancle := context.WithTimeout(context.Background(), time.Second*30)
	defer cancle()

	// get revoved tokens from redis
	revokedTokensJson, err := redisRepo.RedisClient.Get(ctx, configHelper.ServiceConfiguration.RedisRevokedTokensKey).Result()
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not get revoked tokens json: "+err.Error())
		return errorHelper.NewServiceError("something went wrong", 500)
	}

	// unmarshal it
	revokedTokens := []string{}
	if err := json.Unmarshal([]byte(revokedTokensJson), &revokedTokens); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not unmarshal revoked tokens json: "+err.Error())
		return errorHelper.NewServiceError("something went wrong", 500)
	}
	// update revoked tokens slice
	revokedTokens = append(revokedTokens, token)

	// marshal revoked token back to json
	revokedTokensJsonBytes, err := json.Marshal(revokedTokens)
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not marshal revoked tokens: "+err.Error())
		return errorHelper.NewServiceError("something went wrong", 500)
	}

	// set revoked tokens back in database
	if err := redisRepo.RedisClient.Set(ctx, configHelper.ServiceConfiguration.RedisRevokedTokensKey, string(revokedTokensJsonBytes), 0).Err(); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not store revoked tokens in redis: "+err.Error())
		return errorHelper.NewServiceError("something went wrong", 500)
	}

	return nil
}

// IsRevokedToken checks if a token is in the revoked tokens map
func IsRevokedToken(token string) (bool, error) {
	ctx, cancle := context.WithTimeout(context.Background(), time.Second*30)
	defer cancle()

	// get revoved tokens from redis
	revokedTokensJson, err := redisRepo.RedisClient.Get(ctx, configHelper.ServiceConfiguration.RedisRevokedTokensKey).Result()
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not get revoked tokens json: "+err.Error())
		return false, errorHelper.NewServiceError("something went wrong", 500)
	}

	// unmarshal it
	revokedTokens := []string{}
	if err := json.Unmarshal([]byte(revokedTokensJson), &revokedTokens); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not unmarshal revoked tokens json: "+err.Error())
		return false, errorHelper.NewServiceError("something went wrong", 500)
	}

	for _, revokedToken := range revokedTokens {
		if token == revokedToken {
			return true, nil
		}
	}

	return false, nil
}

type Claims struct {
	User entity.User `json:"user"`
	jwt.StandardClaims
}

func GenerateToken(user entity.User) (string, error) {
	claims := Claims{
		User: user,
		StandardClaims: jwt.StandardClaims{
			Issuer:   configHelper.ServiceConfiguration.ServiceName,
			IssuedAt: time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(configHelper.ServiceConfiguration.JWTTokenKey))
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not generate jwt tokeb: "+err.Error())
		return "", errorHelper.NewServiceError("something went wrong", 500)
	}

	return tokenString, nil
}

func ValidateToken(tokenString string) (*entity.User, error) {
	// Parse the token
	claims := Claims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(configHelper.ServiceConfiguration.JWTTokenKey), nil
	})

	// Check for parsing errors
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not validate jwt token: "+err.Error())
		return nil, errorHelper.NewServiceError("invalid token", 401)
	}

	// Check if the token is valid
	if !token.Valid {
		logHelper.LogEvent(logHelper.ErrorLog, "invalid token")
		return nil, errorHelper.NewServiceError("invalid token", 401)
	}

	revoked, err := IsRevokedToken(tokenString)
	if err != nil {
		return nil, err
	}

	if revoked {
		logHelper.LogEvent(logHelper.ErrorLog, "invalid token")
		return nil, errorHelper.NewServiceError("invalid token", 401)
	}

	// Extract user claims
	return &claims.User, nil
}
