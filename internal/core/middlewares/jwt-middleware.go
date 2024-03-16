package middlewares

import (
	"github.com/gin-gonic/gin"
	tokenHelper "realtz-user-service/internal/core/helpers/token-helper"
)

func JWTMiddleware(ctx *gin.Context) {
	authToken := ctx.GetHeader("Token")
	if authToken == "" {
		ctx.AbortWithStatusJSON(401, gin.H{"error": "empty authorization token"})
		return
	}

	// validate token
	_, err := tokenHelper.ValidateToken(authToken)
	if err != nil {
		ctx.AbortWithStatusJSON(401, gin.H{"error": "user unauthorized"})
		return
	}

	ctx.Next()
}
