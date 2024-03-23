package handler

import (
	"context"
	"realtz-user-service/internal/core/domain/eto"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	services "realtz-user-service/internal/core/service"
)

func extractDataFromEvent(event eto.Event) map[string]interface{} {
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		logHelper.LogEvent(logHelper.ErrorLog, "could not assert data in event to a map")
		return nil
	}

	return data
}

// Event handlers go here
func ProductLikedEventHandler(evenJson string) {
	event, _ := eto.EventJsonToEvent(evenJson)
	data := extractDataFromEvent(event)

	UserReference := data["user_reference"].(string)

	services.UserService.Like(context.Background(), UserReference)
}

func ProductUnLikedEventHandler(evenJson string) {
	event, _ := eto.EventJsonToEvent(evenJson)
	data := extractDataFromEvent(event)

	UserReference := data["user_reference"].(string)

	services.UserService.UnLike(context.Background(), UserReference)
}
