package services

import (
	"context"
	"fmt"
	"realtz-user-service/internal/core/domain/dto"
	"realtz-user-service/internal/core/domain/entity"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	mapper "realtz-user-service/internal/core/helpers/mapper"
	otpHelper "realtz-user-service/internal/core/helpers/otp-helper"
	redisHelper "realtz-user-service/internal/core/helpers/redis-helper"
	tokenHelper "realtz-user-service/internal/core/helpers/token-helper"
	verificationHelper "realtz-user-service/internal/core/helpers/verification-helper"
	"realtz-user-service/internal/ports"
	"time"

	// "github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	dbPort    ports.MongoDBPort
	redisPort ports.RedisPort
}

var UserService Service

func NewService(dbPort ports.MongoDBPort, redisPort ports.RedisPort) Service {
	UserService = Service{
		dbPort:    dbPort,
		redisPort: redisPort,
	}

	return UserService
}

func (s Service) SignUp(ctx context.Context, signupDto dto.SignupDto) (interface{}, error) {
	logHelper.LogEvent(logHelper.InfoLog, fmt.Sprintf("attempting to sign up user %v %v", signupDto.Firstname, signupDto.Lastname))

	// create user from signup dto and store in db
	user := mapper.CreateUserFromSignupDto(signupDto)
	_, err := s.dbPort.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	otp, key, _ := otpHelper.GenerateOTP(signupDto.Email)
	// create event data to publish
	eventDataToPublish := struct {
		UserReference string `json:"user_reference" bson:"user_reference"`
		Contact       string `json:"contact"` // phone number or email
		Channel       string `json:"channel"` // can only one of sms|email|all
		Message       string `json:"message"`
		Subject       string `json:"subject"`
		Type          string `json:"type"`
	}{
		UserReference: user.Reference,
		Contact:       signupDto.Email,
		Channel:       "email",
		Message:       fmt.Sprintf("Hi %s, \n\n Welcome to Realtz. Ready to own/rent your first property. Kindly proceed to verify your email with this OTP: %s.", signupDto.Firstname, otp),
		Subject:       "Realtz Signup Notification",
		Type:          "in_app",
	}

	// publish data
	if user.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.USERCREATED, eventDataToPublish)
	}

	// frontend response
	signupResp := struct {
		OTPVerificationKey string `json:"otp_verification_key"`
		Success            bool   `json:"success"`
		Message            string `json:"message"`
	}{
		OTPVerificationKey: key,
		Success:            true,
		Message:            "registration successful",
	}

	return signupResp, nil
}

func (s Service) Login(ctx context.Context, loginDto dto.LoginDto) (interface{}, error) {
	foundUser, err := s.GetUserByEmail(ctx, loginDto.Email)
	if err != nil {
		return nil, err
	}

	user := foundUser.(entity.User)

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginDto.Password)); err != nil {
		return nil, errorHelper.NewServiceError("invalid password", 400)
	}

	// create event data to publish
	eventDataToPublish := struct {
		UserReference string `json:"user_reference" bson:"user_reference"`
		Contact       string `json:"contact"` // phone number or email
		Channel       string `json:"channel"` // can only one of sms|email|all
		Message       string `json:"message"`
		Subject       string `json:"subject"`
		Type          string `json:"type"`
	}{
		UserReference: user.Reference,
		Contact:       user.Email,
		Channel:       "email",
		Message:       fmt.Sprintf("Welcome back %s, You logged in at %s", user.Firstname, time.Now().Format(time.RFC3339)),
		Subject:       "Realtz Login Notification",
		Type:          "in_app",
	}

	// publish data
	if user.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.USERLOGGEDIN, eventDataToPublish)
	}

	token, err := tokenHelper.GenerateToken(user)
	if err != nil {
		return nil, err
	}

	loginData := struct {
		User    entity.User `json:"user"`
		Token   string      `json:"token"`
		Success bool        `json:"success"`
		Message string      `json:"message"`
	}{
		User:    user,
		Token:   token,
		Success: true,
		Message: "login successful",
	}

	return loginData, nil
}

func (s Service) GetUserByEmail(ctx context.Context, email string) (interface{}, error) {
	return s.dbPort.GetUserByEmail(ctx, email)
}

func (s Service) SendOTP(ctx context.Context, currentUser entity.User, otpDto dto.SendOtpDto) (interface{}, error) {

	contact := ""
	if otpDto.Channel == "sms" {
		contact = currentUser.PhoneNumber
	} else {
		contact = currentUser.Email
	}

	otp, key, _ := otpHelper.GenerateOTP(contact)
	// create event data to publish
	eventDataToPublish := struct {
		UserReference string `json:"user_reference" bson:"user_reference"`
		Contact       string `json:"contact"` // phone number or email
		Channel       string `json:"channel"` // can only one of sms|email|all
		Message       string `json:"message"`
		Subject       string `json:"subject"`
		Type          string `json:"type"`
	}{
		UserReference: currentUser.Reference,
		Contact:       contact,
		Channel:       otpDto.Channel,
		Message:       fmt.Sprintf("REALTZ NOTIFICATION\n\nHi %s. Proceed to continue verification with OTP: %s.", currentUser.Firstname, otp),
		Subject:       "Realtz OTP",
		Type:          "sending",
	}

	// publish data
	if currentUser.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.SENDOTP, eventDataToPublish)
	}

	sendOtpResp := struct {
		OTPverificationKey string `json:"otp_verification_key"`
		Message            string `json:"message"`
		Success            bool   `json:"success"`
	}{
		OTPverificationKey: key,
		Message:            "OTP sent. Please stand advised",
		Success:            true,
	}

	return sendOtpResp, nil
}

func (s Service) VerifyEmail(ctx context.Context, currentUser entity.User, verifyEmailDto dto.VerifyEmailDto) (interface{}, error) {
	if !otpHelper.ValidateOtp(verifyEmailDto.OTP, verifyEmailDto.OTPverificationKey) {
		logHelper.LogEvent(logHelper.ErrorLog, "Error validationg otp")
		return nil, errorHelper.NewServiceError("invalid otp", 400)
	}

	foundUser, err := s.GetUserByEmail(ctx, currentUser.Email)
	if err != nil {
		return nil, err
	}

	user := foundUser.(entity.User)

	user.IsEmailVerified = true
	if user.UserType == "user" {
		user.IsVerified = user.IsEmailVerified && user.IsPhoneNumberVerified
	} else {
		user.IsVerified = user.IsEmailVerified && user.IsPhoneNumberVerified && user.IsBvnVerified
	}

	user.LastUpdatedOn = time.Now().Format(time.RFC3339)

	if _, err := s.dbPort.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	eventDataToPublish := struct {
		UserReference string `json:"user_reference" bson:"user_reference"`
		Contact       string `json:"contact"` // phone number or email
		Channel       string `json:"channel"` // can only one of sms|email|all
		Message       string `json:"message"`
		Subject       string `json:"subject"`
		Type          string `json:"type"`
	}{
		UserReference: user.Reference,
		Contact:       user.Email,
		Channel:       "email",
		Message:       fmt.Sprintf("Hi %s.\n\n You have succesfully verified your email address. Kindly proceed to add and verify your phone number too (ignore if you have verified your phone number).", user.Firstname),
		Subject:       "Realtz Verification Notification",
		Type:          "in_app",
	}

	// publish data
	if user.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.EMAILVERIFED, eventDataToPublish)
	}

	emailVerificationResponse := struct {
		Message string `json:"message"`
		Success bool   `json:"success"`
	}{
		Message: "email verification successful",
		Success: true,
	}

	return emailVerificationResponse, nil
}

func (s Service) VerifyPhoneNumber(ctx context.Context, currentUser entity.User, verifyPhoneNumberDto dto.VerifyPhoneNumerDto) (interface{}, error) {
	if !otpHelper.ValidateOtp(verifyPhoneNumberDto.OTP, verifyPhoneNumberDto.OTPverificationKey) {
		logHelper.LogEvent(logHelper.ErrorLog, "Error validationg otp")
		return nil, errorHelper.NewServiceError("invalid otp", 400)
	}

	foundUser, err := s.GetUserByEmail(ctx, currentUser.Email)
	if err != nil {
		return nil, err
	}

	user := foundUser.(entity.User)

	user.IsPhoneNumberVerified = true
	if user.UserType == "user" {
		user.IsVerified = user.IsEmailVerified && user.IsPhoneNumberVerified
	} else {
		user.IsVerified = user.IsEmailVerified && user.IsPhoneNumberVerified && user.IsBvnVerified
	}

	user.LastUpdatedOn = time.Now().Format(time.RFC3339)

	if _, err := s.dbPort.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	eventDataToPublish := struct {
		UserReference string `json:"user_reference" bson:"user_reference"`
		Contact       string `json:"contact"` // phone number or email
		Channel       string `json:"channel"` // can only one of sms|email|all
		Message       string `json:"message"`
		Subject       string `json:"subject"`
		Type          string `json:"type"`
	}{
		Contact:       user.PhoneNumber,
		UserReference: user.Reference,
		Channel:       "sms",
		Message:       fmt.Sprintf("REALTZ NOTIFICATION\n\nHi %s.\n\n You have succesfully verified your phone number. Kindly proceed to add and verify your email address too (ignore if you have verified your email address).", user.Firstname),
		Subject:       "Realtz Verification Notification",
		Type:          "in_app",
	}

	// publish data
	if user.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.PHONENUMBERVERIFIED, eventDataToPublish)
	}

	phoneNumberVerificationResponse := struct {
		Message string `json:"message"`
		Success bool   `json:"success"`
	}{
		Message: "phone pumber verification successful",
		Success: true,
	}

	return phoneNumberVerificationResponse, nil
}

func (s Service) VerifyBvn(ctx context.Context, currentUser entity.User, verifyBvnDto dto.VerifyBvnDto) (interface{}, error) {
	if !otpHelper.ValidateOtp(verifyBvnDto.OTP, verifyBvnDto.OTPverificationKey) {
		logHelper.LogEvent(logHelper.ErrorLog, "Error validationg otp")
		return nil, errorHelper.NewServiceError("invalid otp", 400)
	}

	foundUser, err := s.GetUserByReference(ctx, currentUser.Reference)
	if err != nil {
		return nil, err
	}

	user := foundUser.(entity.User)

	if err := verificationHelper.VerifyBvn(verifyBvnDto.BVN, user.Firstname, user.Lastname); err != nil {
		return nil, err
	}

	user.BVN = verifyBvnDto.BVN
	user.IsBvnVerified = true

	user.IsVerified = user.IsEmailVerified && user.IsPhoneNumberVerified && user.IsBvnVerified

	user.LastUpdatedOn = time.Now().Format(time.RFC3339)

	if _, err := s.dbPort.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	eventDataToPublish := struct {
		UserReference string `json:"user_reference" bson:"user_reference"`
		Contact       string `json:"contact"` // phone number or email
		Channel       string `json:"channel"` // can only one of sms|email|all
		Message       string `json:"message"`
		Subject       string `json:"subject"`
		Type          string `json:"type"`
	}{
		UserReference: user.Reference,
		Contact:       user.PhoneNumber,
		Channel:       "sms",
		Message:       fmt.Sprintf("Hi %s.\n\n You have succesfully added and verified your bvn. Kindly proceed to add and verify your email address and phone number too (ignore if you have verified your email address/phone number).", user.Firstname),
		Subject:       "Realtz Verification Notification",
		Type:          "in_app",
	}

	// publish data
	if user.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.PHONENUMBERVERIFIED, eventDataToPublish)
	}

	phoneNumberVerificationResponse := struct {
		Message string `json:"message"`
		Success bool   `json:"success"`
	}{
		Message: "BVN verification successful",
		Success: true,
	}

	return phoneNumberVerificationResponse, nil
}

func (s Service) StartPasswordRecovery(ctx context.Context, startPasswordRecoveryDto dto.StartPasswordRecoveryDto) (interface{}, error) {
	emailExists, err := s.GetUserByEmail(ctx, startPasswordRecoveryDto.Email)
	if err != nil {
		return nil, err
	}

	user := emailExists.(entity.User)

	return s.SendOTP(ctx, user, dto.SendOtpDto{Channel: "email"})
}

func (s Service) CompletePasswordRecovery(ctx context.Context, completePasswordRecoveryDto dto.CompletePasswordRecoveryDto) (interface{}, error) {
	if !otpHelper.ValidateOtp(completePasswordRecoveryDto.OTP, completePasswordRecoveryDto.OTPverificationKey) {
		logHelper.LogEvent(logHelper.ErrorLog, "Error validatng otp")
		return nil, errorHelper.NewServiceError("invalid otp", 400)
	}

	foundUser, err := s.GetUserByEmail(ctx, completePasswordRecoveryDto.Email)
	if err != nil {
		return nil, err
	}

	user := foundUser.(entity.User)

	newPasswordHash, _ := bcrypt.GenerateFromPassword([]byte(completePasswordRecoveryDto.NewPassword), bcrypt.DefaultCost)

	user.Password = string(newPasswordHash)
	user.LastUpdatedOn = time.Now().Format(time.RFC3339)

	s.dbPort.UpdateUser(ctx, user)

	passwordRecoveryResponse := struct {
		Message string `json:"message"`
		Success bool   `json:"success"`
	}{
		Message: "password update successful",
		Success: true,
	}

	return passwordRecoveryResponse, nil
}

func (s Service) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (interface{}, error) {
	return s.dbPort.GetUserByPhoneNumber(ctx, phoneNumber)
}

func (s Service) GetUserByReference(ctx context.Context, reference string) (interface{}, error) {
	user, err := s.dbPort.GetUserByReference(ctx, reference)
	if err != nil {
		return nil, err
	}

	getUserResponse := struct {
		User    interface{} `json:"user"`
		Message string      `json:"message"`
		Success bool        `json:"success"`
	}{
		User:    user,
		Message: "successfully retrieved user",
		Success: true,
	}

	return getUserResponse, nil
}

func (s Service) UpdatePhoneNumber(ctx context.Context, currentUser entity.User, upddatePhoneNumberDto dto.UpdatePhoneNumberDto) (interface{}, error) {
	phoneNumber := mapper.ConvertPhoneToInternationalFormat(upddatePhoneNumberDto.PhoneNumber)

	phoneNumberExists, _ := s.GetUserByPhoneNumber(ctx, phoneNumber)
	if phoneNumberExists != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "phone number taken by another user")
		return nil, errorHelper.NewServiceError("phone number taken by another user", 409)
	}

	foundUser, _ := s.dbPort.GetUserByEmail(ctx, currentUser.Email)
	user := foundUser.(entity.User)

	user.PhoneNumber = phoneNumber
	user.IsPhoneNumberVerified = false
	user.LastUpdatedOn = time.Now().Format(time.RFC3339)

	if _, err := s.dbPort.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	otp, key, _ := otpHelper.GenerateOTP(upddatePhoneNumberDto.PhoneNumber)
	// create event data to publish
	eventDataToPublish := struct {
		UserReference string `json:"user_reference" bson:"user_reference"`
		Contact       string `json:"contact"` // phone number or email
		Channel       string `json:"channel"` // can only one of sms|email|all
		Message       string `json:"message"`
		Subject       string `json:"subject"`
	}{
		UserReference: user.Reference,
		Contact:       phoneNumber,
		Channel:       "sms",
		Message:       fmt.Sprintf("REALTZ NOTIFICATION\n\nHi %s, \n\n You updated your phone number. Kindly proceed to verify your phone number with this OTP: %s.", user.Firstname, otp),
		Subject:       "Realtz Verification Notification",
	}

	// publish data
	if user.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.UPDATEPHONENUMBER, eventDataToPublish)
	}

	updatePhoneNumberResp := struct {
		OTPverificationKey string `json:"otp_verification_key"`
		Message            string `json:"message"`
		Success            bool   `json:"success"`
	}{
		OTPverificationKey: key,
		Message:            "success. proceed to verify phone number",
		Success:            true,
	}

	return updatePhoneNumberResp, nil
}

func (s Service) Logout(token string) (interface{}, error) {
	tokenHelper.RevokeToken(token)

	logoutResponse := struct {
		Message string `json:"message"`
		Success bool   `json:"success"`
	}{
		Message: "Logout Successful",
		Success: true,
	}
	return logoutResponse, nil
}
