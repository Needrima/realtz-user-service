package repository

import (
	"context"
	"fmt"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"

	"cloud.google.com/go/storage"
	firebaseStorage "firebase.google.com/go/storage"
	"github.com/google/uuid"
)

type fireBaseClient struct {
	storageClient *firebaseStorage.Client
}

func NewFirebaseClient(storageClient *firebaseStorage.Client) fireBaseClient {
	return fireBaseClient{
		storageClient: storageClient,
	}
}

func (f fireBaseClient) UploadProfileImageToCloudAndGetLink(bucketName, userReference string, image []byte) (string, error) {
	ctx := context.Background()
	bucketHandle, err := f.storageClient.Bucket(bucketName)
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "error decoding video base64: "+err.Error())
		return "", errorHelper.NewServiceError("something went wrong", 500)
	}

	imageName := fmt.Sprintf("%s-profile-image.jpeg", userReference) // e.g 46fee48b-4e03-4cad-b229-19ea8c0cbe0c-profile-image.jpeg

	objectHandle := bucketHandle.Object(imageName)

	logHelper.LogEvent(logHelper.InfoLog, "deleting old profile image")

	if err := objectHandle.Delete(ctx); err != nil && err != storage.ErrObjectNotExist {
		logHelper.LogEvent(logHelper.ErrorLog, fmt.Sprintf("could not delete old profile image for user: %s, error: %v", userReference, err))
		return "", errorHelper.NewServiceError("something went wrong", 500)
	}
	logHelper.LogEvent(logHelper.InfoLog, "successfully deleted old profile image for user: "+userReference)

	writer := objectHandle.NewWriter(ctx)

	// setting this metadata is important for firebase
	writer.ObjectAttrs.Metadata = map[string]string{"firebaseStorageDownloadToken": uuid.New().String()}

	writer.ACL = []storage.ACLRule{
		{Entity: storage.AllUsers, Role: storage.RoleReader},
	}

	logHelper.LogEvent(logHelper.InfoLog, "uploading new profile image for user: "+userReference)
	if _, err := writer.Write(image); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "error writing to firebase bucket: "+err.Error())
		return "", errorHelper.NewServiceError("something went wrong", 500)
	}
	writer.Close() // close writer so object attributes will be available

	attrs, err := objectHandle.Attrs(context.Background())
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "error getting video object atrributes: "+err.Error())
		return "", errorHelper.NewServiceError("something went wrong", 500)
	}

	return attrs.MediaLink, nil
}
