package main

import (
	"os"
	handler "realtz-user-service/internal/adapter/http-handler"
	mongoRepo "realtz-user-service/internal/adapter/repository/mongodb"
	redisRepo "realtz-user-service/internal/adapter/repository/redis"
	"realtz-user-service/internal/adapter/routes"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
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

	// start api on service level
	service := services.NewService(mongoRepo, redisRepo)

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

	// go func() {
	// 	redisRepo.SubsribeToEvent(redisHelper.USERCREATED, redisHelper.SendNotificationHandler)
	// }()

	select {}
}
