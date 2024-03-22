package dto

type SignupDto struct {
	UserType        string `json:"user_type" bson:"user_type" binding:"required,eq=user|eq=agent"`
	Firstname       string `json:"firstname" bson:"firstname" binding:"required,min=3"`
	Lastname        string `json:"lastname" bson:"lastname" binding:"required,min=3"`
	Email           string `json:"email" bson:"email" binding:"required,email"`
	PhoneNumber     string `json:"phone_number" bson:"phone_number" binding:"required,valid_phone_number"`
	Password        string `json:"password" bson:"password" binding:"required,valid_password"`
	ConfirmPassword string `json:"confirm_password" bson:"confirm_password" binding:"required,eqfield=Password"`
}

type LoginDto struct {
	Email    string `json:"email" bson:"email" binding:"required,email"`
	Password string `json:"password" bson:"password" binding:"required,valid_password"`
}

type SendOtpDto struct {
	Channel string `json:"channel" bson:"channel" binding:"required,eq=sms|eq=email|eq=all"`
}

type SendOtpOnboardingDto struct {
	Channel     string `json:"channel" bson:"channel" binding:"required,eq=sms|eq=email|eq=all"`
	Email       string `json:"email" bson:"email" binding:"required_if=Channel email"`
	PhoneNumber string `json:"phone_number" bson:"phone_number" binding:"required_if=Channel sms"`
}

type VerifyEmailDto struct {
	OTP                string `json:"otp" binding:"required,len=6"`
	OTPverificationKey string `json:"otp_verification_key" binding:"required"`
}

type VerifyEmailOnboardingDto struct {
	OTP                string `json:"otp" binding:"required,len=6"`
	OTPverificationKey string `json:"otp_verification_key" binding:"required"`
	Email              string `json:"email" bson:"email" binding:"required,email"`
}

type UpdatePhoneNumberDto struct {
	PhoneNumber string `json:"phone_number" bson:"phone_number" binding:"required,valid_phone_number"`
}

type VerifyPhoneNumerDto struct {
	OTP                string `json:"otp" binding:"required,len=6"`
	OTPverificationKey string `json:"otp_verification_key" binding:"required"`
}

type VerifyBvnDto struct {
	OTP                string `json:"otp" binding:"required,len=6"`
	OTPverificationKey string `json:"otp_verification_key" binding:"required"`
	BVN                string `json:"bvn" bson:"bvn" binding:"required,len=11"`
}

type StartPasswordRecoveryDto struct {
	Email string `json:"email" bson:"email" binding:"required,email"`
}

type CompletePasswordRecoveryDto struct {
	OTP                string `json:"otp" binding:"required,len=6"`
	OTPverificationKey string `json:"otp_verification_key" binding:"required"`
	NewPassword        string `json:"new_password" bson:"new_password" binding:"required,valid_password"`
	ConfirmPassword string `json:"confirm_password" bson:"confirm_password" binding:"required,eqfield=NewPassword"`
	Email              string `json:"email" bson:"email" binding:"required,email"`
}
