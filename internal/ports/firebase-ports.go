package ports

type FirebasePort interface {
	UploadProfileImageToCloudAndGetLink(bucketName, userReference string, image []byte) (string, error)
}
