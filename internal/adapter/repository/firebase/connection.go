package repository

import (
	"context"
	"os"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"

	firebase "firebase.google.com/go"
	"google.golang.org/api/option"
)

func ConnectToFirebase() fireBaseClient {
	opt := option.WithCredentialsFile(configHelper.ServiceConfiguration.FirebaseAccountKeyPath)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		logHelper.LogEvent(logHelper.DangerLog, "could not connect to firebase: "+err.Error())
		os.Exit(1)
	}

	client, err := app.Storage(context.Background())
	if err != nil {
		logHelper.LogEvent(logHelper.DangerLog, "could not get storage client: "+err.Error())
		os.Exit(1)
	}

	return NewFirebaseClient(client)
}
