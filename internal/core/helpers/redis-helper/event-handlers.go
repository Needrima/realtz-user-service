package helpers

import (
	"realtz-user-service/internal/core/domain/eto"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
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
