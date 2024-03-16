package middlewares

import (
	"time"

	"github.com/gin-contrib/cors"
)

var CORSMiddleware = cors.New(cors.Config{
	AllowOrigins:     []string{"*"},
	AllowMethods:     []string{"PUT", "GET", "POST", "DELETE", "OPTIONS", "HEAD"},
	AllowHeaders:     []string{"Content-Type", "Token", "Content-Length"},
	ExposeHeaders:    []string{"Content-Type", "Token", "Content-Length"},
	AllowCredentials: true,
	AllowOriginFunc: func(origin string) bool {
		return true
	},
	MaxAge: 12 * time.Hour,
})
