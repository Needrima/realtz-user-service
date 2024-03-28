package main

import (
	"os"
	eventHandler "realtz-user-service/internal/adapter/event-handler"
	handler "realtz-user-service/internal/adapter/http-handler"
	firebaseRepo "realtz-user-service/internal/adapter/repository/firebase"
	mongoRepo "realtz-user-service/internal/adapter/repository/mongodb"
	redisRepo "realtz-user-service/internal/adapter/repository/redis"
	"realtz-user-service/internal/adapter/routes"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	redisHelper "realtz-user-service/internal/core/helpers/redis-helper"
	validationHelper "realtz-user-service/internal/core/helpers/validation-helper"
	services "realtz-user-service/internal/core/service"
)

func main() {
	// iniitalize logger
	logHelper.InitializeLogger()

	// initialize struct validation for gin binding
	validationHelper.InitBindingValidation()

	// start api on database level (mongodb and redis)
	mongoRepo := mongoRepo.ConnectToMongoDB()
	redisRepo := redisRepo.ConnectToRedis()
	firebaseRepo := firebaseRepo.ConnectToFirebase()

	// start api on service level
	service := services.NewService(mongoRepo, redisRepo, firebaseRepo)

	// start api on http level
	handler := handler.NewHTTPHandler(service)
	router := routes.SetupRouter(handler)

	config := configHelper.ServiceConfiguration
	go func() {
		logHelper.LogEvent(logHelper.InfoLog, "starting server on port "+config.ServicePort)
		if err := router.Run(":" + config.ServicePort); err != nil {
			logHelper.LogEvent(logHelper.DangerLog, "could not start server "+err.Error())
			os.Exit(1)
		}
	}()

	go func() {
		redisRepo.SubsribeToEvent(redisHelper.PRODUCTLIKED, eventHandler.ProductLikedEventHandler)
	}()

	go func() {
		redisRepo.SubsribeToEvent(redisHelper.PRODUCTUNLIKED, eventHandler.ProductUnLikedEventHandler)
	}()

	select {}
}
