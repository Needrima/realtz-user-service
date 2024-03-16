package eto

import (
	"encoding/json"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	"time"

	"github.com/google/uuid"
)

type Event struct {
	Reference string      `json:"reference"`
	CreatedOn string      `json:"created_on"`
	Publisher string      `json:"publisher"`
	Data      interface{} `json:"data"`
}

func NewEvent(data interface{}) Event {
	return Event{
		Reference: uuid.New().String(),
		CreatedOn: time.Now().Format(time.RFC3339),
		Publisher: configHelper.ServiceConfiguration.ServiceName,
		Data:      data,
	}
}

func EventJsonToEvent(eventJson string) (Event, error) {
	event := Event{}
	if err := json.Unmarshal([]byte(eventJson), &event); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not convert event json to event: "+err.Error())
		return Event{}, errorHelper.NewServiceError("something went wrong", 500)
	}

	return event, nil
}

func (e *Event) ToJSON() string {
	jsonBytes, err := json.Marshal(e)

	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "could not convert event to json: "+err.Error())
		return ""
	}

	return string(jsonBytes)
}
