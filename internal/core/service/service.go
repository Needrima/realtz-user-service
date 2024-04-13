package services

import (
	"context"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"path/filepath"
	"realtz-user-service/internal/core/domain/dto"
	"realtz-user-service/internal/core/domain/entity"
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	mapper "realtz-user-service/internal/core/helpers/mapper"
	miscHelper "realtz-user-service/internal/core/helpers/misc-helper"
	otpHelper "realtz-user-service/internal/core/helpers/otp-helper"
	redisHelper "realtz-user-service/internal/core/helpers/redis-helper"
	tokenHelper "realtz-user-service/internal/core/helpers/token-helper"
	verificationHelper "realtz-user-service/internal/core/helpers/verification-helper"
	"realtz-user-service/internal/ports"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	dbPort       ports.MongoDBPort
	redisPort    ports.RedisPort
	firebasePort ports.FirebasePort
}

var UserService Service

func NewService(dbPort ports.MongoDBPort, redisPort ports.RedisPort, firebasePort ports.FirebasePort) Service {
	UserService = Service{
		dbPort:       dbPort,
		redisPort:    redisPort,
		firebasePort: firebasePort,
	}

	return UserService
}

func (s Service) SignUp(ctx context.Context, signupDto dto.SignupDto) (interface{}, error) {
	logHelper.LogEvent(logHelper.InfoLog, fmt.Sprintf("attempting to sign up user %v %v", signupDto.Username, signupDto.Lastname))

	if !signupDto.Agreement {
		return nil, errorHelper.NewServiceError("You have not agreed to terms and conditions", 400)
	}

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
		Message:       fmt.Sprintf("Hi %s, \n\n Welcome to Realtz. Ready to own/rent your first property. Kindly proceed to verify your email with this OTP: %s.", signupDto.Username, otp),
		Subject:       "Realtz Signup Notification",
		Type:          "in_app",
	}

	// publish data
	s.redisPort.PublishEvent(ctx, redisHelper.USERCREATED, eventDataToPublish)

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
		Message:       fmt.Sprintf("Welcome back %s, You logged in at %s", user.Username, time.Now().Format(time.RFC3339)),
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
		Message:       fmt.Sprintf("REALTZ NOTIFICATION\n\nHi %s. Proceed to continue verification with OTP: %s.", currentUser.Username, otp),
		Subject:       "Realtz OTP",
		Type:          "sending",
	}

	// publish data
	s.redisPort.PublishEvent(ctx, redisHelper.SENDOTP, eventDataToPublish)

	sendOtpResp := struct {
		OTP string `json:"otp"`
		OTPverificationKey string `json:"otp_verification_key"`
		Message            string `json:"message"`
		Success            bool   `json:"success"`
	}{
		OTP: otp,
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
		Message:       fmt.Sprintf("Hi %s.\n\n You have succesfully verified your email address. Kindly proceed to verify your phone number too. Kindly ignore if you have verified your phone number.", user.Username),
		Subject:       "Realtz Verification Notification",
		Type:          "in_app",
	}

	// publish data
	if user.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.EMAILVERIFED, eventDataToPublish)
	}

	emailVerificationResponse := struct {
		UpdatedUser interface{} `json:"updated_user"`
		Message string `json:"message"`
		Success bool   `json:"success"`
	}{
		UpdatedUser: user,
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
		Message:       fmt.Sprintf("REALTZ NOTIFICATION\n\nHi %s.\n\n You have succesfully verified your phone number. Kindly proceed to verify your email address too. Kindly ignore if you have verified your email address.", user.Username),
		Subject:       "Realtz Verification Notification",
		Type:          "in_app",
	}

	// publish data
	if user.IsEmailVerified {
		s.redisPort.PublishEvent(ctx, redisHelper.PHONENUMBERVERIFIED, eventDataToPublish)
	}

	phoneNumberVerificationResponse := struct {
		UpdatedUser interface{} `json:"updated_user"`
		Message string `json:"message"`
		Success bool   `json:"success"`
	}{
		UpdatedUser: user,
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

	foundUser, err := s.dbPort.GetUserByReference(ctx, currentUser.Reference)
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
		Message:       fmt.Sprintf("Hi %s.\n\n You have succesfully added and verified your bvn. Kindly proceed to verify your email address and phone number too. Kindly ignore if you have verified your email address/phone number.", user.Username),
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
	foundUser, err := s.GetUserByEmail(ctx, startPasswordRecoveryDto.Email)
	if err != nil {
		return nil, err
	}

	user := foundUser.(entity.User)

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
		Message:       fmt.Sprintf("Hi %s, \n\n. You recently changed your password. Now you can login and continue seeking your dream property.", user.Username),
		Subject:       "Realtz Password Reset Confirmation",
		Type:          "in_app",
	}

	// publish data
	s.redisPort.PublishEvent(ctx, redisHelper.PASSWORDRESET, eventDataToPublish)

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
		Message:       fmt.Sprintf("REALTZ NOTIFICATION\n\nHi %s, \n\n You updated your phone number. Kindly proceed to verify your phone number with this OTP: %s.", user.Username, otp),
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

func (s Service) IncrementListing(ctx context.Context, reference string) (interface{}, error) {
	foundUser, err := s.dbPort.GetUserByReference(ctx, reference)
	if err != nil {
		return nil, err
	}
	user := foundUser.(entity.User)
	user.NumProducts++
	return s.dbPort.UpdateUser(ctx, user)
}

func (s Service) IncrementLike(ctx context.Context, reference string) (interface{}, error) {
	foundUser, err := s.dbPort.GetUserByReference(ctx, reference)
	if err != nil {
		return nil, err
	}
	user := foundUser.(entity.User)
	user.NumLikes++
	return s.dbPort.UpdateUser(ctx, user)
}

func (s Service) DecrementLike(ctx context.Context, reference string) (interface{}, error) {
	foundUser, err := s.dbPort.GetUserByReference(ctx, reference)
	if err != nil {
		return nil, err
	}
	user := foundUser.(entity.User)
	user.NumLikes--
	return s.dbPort.UpdateUser(ctx, user)
}

func (s Service) IncrementSave(ctx context.Context, reference string) (interface{}, error) {
	foundUser, err := s.dbPort.GetUserByReference(ctx, reference)
	if err != nil {
		return nil, err
	}
	user := foundUser.(entity.User)
	user.NumSaves++
	return s.dbPort.UpdateUser(ctx, user)
}

func (s Service) DecrementSave(ctx context.Context, reference string) (interface{}, error) {
	foundUser, err := s.dbPort.GetUserByReference(ctx, reference)
	if err != nil {
		return nil, err
	}
	user := foundUser.(entity.User)
	user.NumSaves--
	return s.dbPort.UpdateUser(ctx, user)
}

func (s Service) UploadProfileImage(ctx context.Context, currentUser entity.User, fileHeader *multipart.FileHeader) (interface{}, error) {
	if fileHeader.Size > 2<<(10*2) { // if file is greater than 2MB
		logHelper.LogEvent(logHelper.InfoLog, "file greater than 2MB")
		return nil, errorHelper.NewServiceError("file is greater than 2MB", 400)
	}

	fileExt := filepath.Ext(fileHeader.Filename)
	if _, found := miscHelper.Found[string]([]string{".jpg", ".jpeg", ".png"}, fileExt); !found {
		logHelper.LogEvent(logHelper.InfoLog, "unaccepted image file type")
		return nil, errorHelper.NewServiceError("unaccepted image file type, image must be .jpg, .jpeg, .png", 400)
	}

	file, err := fileHeader.Open()
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "opening file header, error: "+err.Error())
		return nil, errorHelper.NewServiceError("could not upload image", 500)
	}

	imageBytes, err := io.ReadAll(file)
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "reading bytes from file, error: "+err.Error())
		return nil, errorHelper.NewServiceError("could not upload image", 500)
	}

	newImageLink, err := s.firebasePort.UploadProfileImageToCloudAndGetLink(
		configHelper.ServiceConfiguration.FirebaseStorageBucket,
		currentUser.Reference,
		imageBytes,
	)
	if err != nil {
		return nil, err
	}

	foundUser, err := s.dbPort.GetUserByReference(ctx, currentUser.Reference)
	if err != nil {
		return nil, err
	}
	user := foundUser.(entity.User)

	user.Image = newImageLink

	s.dbPort.UpdateUser(ctx, user)

	updateProfileImageResp := struct {
		NewImageLink string `json:"new_image_link"`
		Message      string `json:"message"`
		Success      bool   `json:"success"`
	}{
		NewImageLink: newImageLink,
		Message:      "profile image uploaded successfully",
		Success:      true,
	}

	return updateProfileImageResp, nil
}

func (s Service) EditProfile(ctx context.Context, currentUser entity.User, editProfileDto dto.EditProfileDto) (interface{}, error) {

	if editProfileDto.Username != "" {
		if len(editProfileDto.Username) < 3 {
			return nil, errorHelper.NewServiceError("username can't be less than 3 characters", 400)
		}

		foundUser, _ := s.dbPort.GetUserByUsername(ctx, editProfileDto.Username)

		if foundUser != nil {
			user := foundUser.(entity.User)
			if strings.EqualFold(user.Username, editProfileDto.Username) {
				return nil, errorHelper.NewServiceError("username already belongs to you", 409)
			}

			return nil, errorHelper.NewServiceError("username has ben taken", 409)
		}
	}

	foundUser, err := s.dbPort.GetUserByReference(ctx, currentUser.Reference)
	if err != nil {
		return nil, err
	}
	user := foundUser.(entity.User)

	if editProfileDto.Username != "" {
		user.Username = editProfileDto.Username
	}

	if editProfileDto.Bio != "" {
		if len(strings.TrimSpace(editProfileDto.Bio)) < 10 {
			return nil, errorHelper.NewServiceError("bio can't be less than 10 characters", 400)
		}
		user.Bio = editProfileDto.Bio
	}

	_, err = s.dbPort.UpdateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	editProfileResp := struct {
		UpdatedUser interface{} `json:"updated_user"`
		Message     string      `json:"message"`
		Success     bool        `json:"success"`
	}{
		UpdatedUser: user,
		Message:     "profile update successful",
		Success:     true,
	}

	return editProfileResp, nil
}

func (s Service) RateUser(ctx context.Context, currentUser entity.User, reference, rating string) (interface{}, error) {
	ratingInt, err := strconv.Atoi(rating)
	if err != nil {
		return nil, errorHelper.NewServiceError("invalid rating", 400)
	}

	foundUserToRate, err := s.dbPort.GetUserByReference(ctx, reference)
	if err != nil {
		return nil, err
	}

	userToRate := foundUserToRate.(entity.User)
	if _, found := miscHelper.Found[string](userToRate.RatedBy, currentUser.Reference); found {
		return nil, errorHelper.NewServiceError("you already rated this agent", 400)
	}

	// calculate new average rating
	sum := 0.0
	if len(userToRate.RatedBy) == 0 {
		sum = float64(userToRate.StarRating*1 + ratingInt)
		newRating := math.Ceil(sum/2)
		userToRate.StarRating = int(newRating)
	} else {
		sum = float64(userToRate.StarRating*len(userToRate.RatedBy) + ratingInt)
		newRating := math.Ceil(sum / float64((len(userToRate.RatedBy) + 1)))
		userToRate.StarRating = int(newRating)
	}

	userToRate.RatedBy = append(userToRate.RatedBy, currentUser.Reference)

	s.dbPort.UpdateUser(ctx, userToRate)

	eventDataToPublish := struct {
		UserReference string `json:"user_reference" bson:"user_reference"`
		Contact       string `json:"contact"` // phone number or email
		Channel       string `json:"channel"` // can only one of sms|email|all
		Message       string `json:"message"`
		Subject       string `json:"subject"`
		Type          string `json:"type"`
	}{
		UserReference: userToRate.Reference,
		Contact:       userToRate.Email,
		Channel:       "email",
		Message:       fmt.Sprintf("Hi %s, \n\n You just received a star rating of %s making your average rating %d.", userToRate.Username, rating, userToRate.StarRating),
		Subject:       "Realtz Notification",
		Type:          "in_app",
	}

	// publish data
	s.redisPort.PublishEvent(ctx, redisHelper.USERRATED, eventDataToPublish)

	// frontend response
	rateUserResp := struct {
		UpdatedUser interface{} `json:"updated_user"`
		Message     string      `json:"message"`
		Success     bool        `json:"success"`
	}{
		UpdatedUser: userToRate,
		Message:     fmt.Sprintf("you dropped a rating for %s", userToRate.Username),
		Success:     true,
	}

	return rateUserResp, nil
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
