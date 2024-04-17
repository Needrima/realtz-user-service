package routes

import (
	"realtz-user-service/docs"
	handler "realtz-user-service/internal/adapter/http-handler"
	"realtz-user-service/internal/core/middlewares"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRouter(handler handler.HttpHandler) *gin.Engine {
	//Swagger meta data
	docs.SwaggerInfo.Title = "Realtz User Service"
	docs.SwaggerInfo.Description = "User microservice for realtz app"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.BasePath = "/api/user"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}

	router := gin.Default()
	router.Use(middlewares.CORSMiddleware)

	userApiGroup := router.Group("/api/user")
	{
		userApiGroup.POST("/signup", handler.SignUp)
		userApiGroup.POST("/login", handler.Login)
		userApiGroup.POST("/verify-email", handler.VerifyEmailOnboarding)
		userApiGroup.POST("/start-password-recovery", handler.StartPasswordRecovery)
		userApiGroup.POST("/complete-password-recovery", handler.CompletePasswordRecovery)
		userApiGroup.POST("/send-otp", handler.SendOTPOnBoarding)
	}

	userApiAuthGroup := router.Group("/api/user/auth")
	userApiAuthGroup.Use(middlewares.JWTMiddleware)
	{
		userApiAuthGroup.POST("/send-otp", handler.SendOTP)
		userApiAuthGroup.POST("/verify-email", handler.VerifyEmail)
		userApiAuthGroup.POST("/update-phone", handler.UpdatePhoneNumber)
		userApiAuthGroup.POST("/verify-phone", handler.VerifyPhoneNumber)
		userApiAuthGroup.POST("/verify-bvn", handler.VerifyBvn)
		userApiAuthGroup.GET("/get-user/:user_reference", handler.GetUserByReference)
		userApiAuthGroup.POST("/upload-profile-image", handler.UploadProfileImage)
		userApiAuthGroup.POST("/edit-profile", handler.EditProfile)
		userApiAuthGroup.GET("/rate-user/:user_reference/:rating", handler.RateUser)
		userApiAuthGroup.GET("/delete-account", handler.DeleteAccount)
		userApiAuthGroup.GET("/logout", handler.Logout)
	}

	// for swagger docs
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return router
}
