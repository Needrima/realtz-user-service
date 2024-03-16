package helpers

type ServiceError struct {
	Message string
	Code    int
}

func NewServiceError(message string, code int) ServiceError {
	return ServiceError{
		Message: message,
		Code:    code,
	}
}

func (e ServiceError) Error() string {
	return e.Message
}
