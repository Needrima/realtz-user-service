package helpers

import (
	"encoding/json"
	"log"
	"os"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	"time"
)

type LogLevel string

const (
	InfoLog    LogLevel = "INFO"
	ErrorLog   LogLevel = "ERROR"
	WarningLog LogLevel = "WARNING"
	SuccessLog LogLevel = "SUCCESS"
	DangerLog  LogLevel = "DANGER"
)

// Sets the logger to log to log file
func InitializeLogger() {
	config := configHelper.ServiceConfiguration
	logDir := config.LogDir
	_ = os.Mkdir(logDir, os.ModePerm)

	f, err := os.OpenFile(logDir+config.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening log file: %v", err)
	}
	log.SetFlags(0)
	log.SetOutput(f)
}

// LogEvent logs a message to the log file.
// check the env to check location of log file
func LogEvent(level LogLevel, message interface{}) {

	data, err := json.Marshal(struct {
		TimeStamp string      `json:"@timestamp"`
		Level     LogLevel    `json:"level"`
		AppName   string      `json:"app_name"`
		Message   interface{} `json:"message"`
	}{
		TimeStamp: time.Now().Format(time.RFC3339),
		AppName:   configHelper.ServiceConfiguration.ServiceName,
		Message:   message,
		Level:     level,
	})

	if err != nil {
		log.Println("error marshalling event:", err)
		return
	}

	log.Println(string(data))
}
