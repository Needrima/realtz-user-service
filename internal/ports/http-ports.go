package ports

import (
	"context"
	"mime/multipart"
	"realtz-user-service/internal/core/domain/dto"
	"realtz-user-service/internal/core/domain/entity"
)

type HTTPPort interface {
	SignUp(ctx context.Context, signupDto dto.SignupDto) (interface{}, error)
	Login(ctx context.Context, loginDto dto.LoginDto) (interface{}, error)
	SendOTP(ctx context.Context, currentUser entity.User, otpDto dto.SendOtpDto) (interface{}, error)
	VerifyEmail(ctx context.Context, currentUser entity.User, verifyEmailDto dto.VerifyEmailDto) (interface{}, error)
	VerifyPhoneNumber(ctx context.Context, currentUser entity.User, verifyPhoneNumberDto dto.VerifyPhoneNumerDto) (interface{}, error)
	VerifyBvn(ctx context.Context, currentUser entity.User, verifyPhoneNumberDto dto.VerifyBvnDto) (interface{}, error)
	StartPasswordRecovery(ctx context.Context, startPasswordRecoveryDto dto.StartPasswordRecoveryDto) (interface{}, error)
	CompletePasswordRecovery(ctx context.Context, completePasswordRecoveryDto dto.CompletePasswordRecoveryDto) (interface{}, error)
	GetUserByEmail(ctx context.Context, email string) (interface{}, error)
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (interface{}, error)
	GetUserByReference(ctx context.Context, reference string) (interface{}, error)
	UpdatePhoneNumber(ctx context.Context, currentUser entity.User, upddatePhoneNumberDto dto.UpdatePhoneNumberDto) (interface{}, error)
	IncrementLike(ctx context.Context, reference string) (interface{}, error)
	DecrementLike(ctx context.Context, reference string) (interface{}, error)
	IncrementSave(ctx context.Context, reference string) (interface{}, error)
	DecrementSave(ctx context.Context, reference string) (interface{}, error)
	UploadProfileImage(ctx context.Context, currentUser entity.User, fileHeader *multipart.FileHeader) (interface{}, error)
	EditProfile(ctx context.Context, currentUser entity.User, editProfileDto dto.EditProfileDto) (interface{}, error)
	ChangePassword(ctx context.Context, currentUser entity.User, changePasswordDto dto.ChangePasswordDto) (interface{}, error)
	SwitchToAgentDto(ctx context.Context, currentUser entity.User, changePasswordDto dto.SwitchToAgentDto) (interface{}, error)
	RateUser(ctx context.Context, currentUser entity.User, reference, rating string) (interface{}, error)
	DeleteAccount(ctx context.Context, currentUser entity.User) (interface{}, error)
	Logout(token string) (interface{}, error)
}
