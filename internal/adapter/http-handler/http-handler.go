package handler

import (
	"fmt"
	"realtz-user-service/internal/core/domain/dto"
	"realtz-user-service/internal/core/domain/entity"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	tokenHelper "realtz-user-service/internal/core/helpers/token-helper"
	"realtz-user-service/internal/ports"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type HttpHandler struct {
	httpPort ports.HTTPPort
}

func NewHTTPHandler(httpPort ports.HTTPPort) HttpHandler {
	return HttpHandler{
		httpPort: httpPort,
	}
}

// @Summary Signup
// @Description Registering a new user
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {object} interface{} "User Created Successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Failure 409 {object} errorHelper.ServiceError "user already exists"
// @Param requestBody body dto.SignupDto true "Signuprequest body"
// @Router /signup [post]
func (h HttpHandler) SignUp(c *gin.Context) {
	body := dto.SignupDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding signup request body: "+err.Error())

		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				// fmt.Printf("Field: %s, Tag: %s, ActualTag: %s, Value: %v\n",
				// valErr.Field(), valErr.Tag(), valErr.ActualTag(), valErr.Value())
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	logHelper.LogEvent(logHelper.InfoLog, fmt.Sprintf("received request payload for signup request for %v %v", body.Firstname, body.Lastname))

	response, err := h.httpPort.SignUp(c.Request.Context(), body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, response)
}

// @Summary Login
// @Description Login to account
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {object} interface{} "Login succesful"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Failure 404 {object} errorHelper.ServiceError "user not found"
// @Param requestBody body dto.LoginDto true "Login request body"
// @Router /login [post]
func (h HttpHandler) Login(c *gin.Context) {
	body := dto.LoginDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding login request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	response, err := h.httpPort.Login(c.Request.Context(), body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Send OTP
// @Description Send OTP for different verification processes
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "OTP sent successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.SendOtpDto true "Send OTP request body"
// @Router /auth/send-otp [post]
func (h HttpHandler) SendOTP(c *gin.Context) {
	body := dto.SendOtpDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding send otp request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.SendOTP(c.Request.Context(), *currentUser, body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Send OTP onboarding
// @Description Send OTP for different verification processes during onboarding
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {object} interface{} "OTP sent successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.SendOtpOnboardingDto true "Send OTP request body"
// @Router /send-otp [post]
func (h HttpHandler) SendOTPOnBoarding(c *gin.Context) {
	body := dto.SendOtpOnboardingDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding send otp request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	currentUser := entity.User{
		Email:       body.Email,
		PhoneNumber: body.PhoneNumber,
	}

	sendOtpDto := dto.SendOtpDto{
		Channel: body.Channel,
	}

	response, err := h.httpPort.SendOTP(c.Request.Context(), currentUser, sendOtpDto)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Verify email
// @Description Verify email when user skipped email verification during onboarding
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "Email verified successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.VerifyEmailDto true "Verify email request body"
// @Router /auth/verify-email [post]
func (h HttpHandler) VerifyEmail(c *gin.Context) {
	body := dto.VerifyEmailDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding email verification request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.VerifyEmail(c.Request.Context(), *currentUser, body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Verify email on onboarding
// @Description Verify email when user is just signing up
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {object} interface{} "Email verified successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.VerifyEmailOnboardingDto true "Verify email request body"
// @Router /verify-email [post]
func (h HttpHandler) VerifyEmailOnboarding(c *gin.Context) {
	body := dto.VerifyEmailOnboardingDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding email verification request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	user := entity.User{Email: body.Email}
	verifyEmailDto := dto.VerifyEmailDto{OTP: body.OTP, OTPverificationKey: body.OTPverificationKey}

	response, err := h.httpPort.VerifyEmail(c.Request.Context(), user, verifyEmailDto)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Update Phone Number
// @Description Add or change user's phone number
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "Phone number added / changed successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.UpdatePhoneNumberDto true "Udpate phone number request body"
// @Router /auth/update-phone [post]
func (h HttpHandler) UpdatePhoneNumber(c *gin.Context) {
	body := dto.UpdatePhoneNumberDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding updating phone number request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.UpdatePhoneNumber(c.Request.Context(), *currentUser, body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Verify update Phone Number
// @Description Verify a user's phone number
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "Phone number verified successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.VerifyPhoneNumerDto true "Verify phone number request body"
// @Router /auth/verify-phone [post]
func (h HttpHandler) VerifyPhoneNumber(c *gin.Context) {
	body := dto.VerifyPhoneNumerDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding phone number verification request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.VerifyPhoneNumber(c.Request.Context(), *currentUser, body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Verify BVN
// @Description Verify a user's bank verification number
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "BVN verified successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.VerifyBvnDto true "Verify phone number request body"
// @Router /auth/verify-bvn [post]
func (h HttpHandler) VerifyBvn(c *gin.Context) {
	body := dto.VerifyBvnDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding phone number verification request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.VerifyBvn(c.Request.Context(), *currentUser, body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Start Password recovery
// @Description Send OTP when user forget's password and tries recovering it
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {string} interface{} "OTP sent"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Failure 404 {object} errorHelper.ServiceError "user doesn't exist"
// @Param requestBody body dto.StartPasswordRecoveryDto true "Start password recovery request body"
// @Router /start-password-recovery [post]
func (h HttpHandler) StartPasswordRecovery(c *gin.Context) {
	body := dto.StartPasswordRecoveryDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding start password recovery request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	response, err := h.httpPort.StartPasswordRecovery(c.Request.Context(), body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Complete Password recovery
// @Description Change User password
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {string} interface{} "Password changed successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Failure 404 {object} errorHelper.ServiceError "user doesn't exist"
// @Param requestBody body dto.CompletePasswordRecoveryDto true "Complete password recovery request body"
// @Router /complete-password-recovery [post]
func (h HttpHandler) CompletePasswordRecovery(c *gin.Context) {
	body := dto.CompletePasswordRecoveryDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding complete password recovery request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	response, err := h.httpPort.CompletePasswordRecovery(c.Request.Context(), body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Get User
// @Description Retrieve user by user reference
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {string} interface{} "User retrieved successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Failure 404 {object} errorHelper.ServiceError "user not found"
// @Param user_reference path string true "reference of the user to be queried"
// @Router /auth/get-user/{user_reference} [get]
func (h HttpHandler) GetUserByReference(c *gin.Context) {
	userReference := c.Param("user_reference")

	response, err := h.httpPort.GetUserByReference(c.Request.Context(), userReference)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Upload Profile image
// @Description Upload or replace user profile image
// @Tags User
// @Accept multipart/form-data
// @Produce json
// @Param Token header string true "Authentication token"
// @Param profile_image formData file true "Profile Image to upload"
// @Success 200 {string} interface{} "Image Upload successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Failure 404 {object} errorHelper.ServiceError "user not found"
// @Router /auth/upload-profile-image [post]
func (h HttpHandler) UploadProfileImage(c *gin.Context) {

	fileHeader, err := c.FormFile("profile_image")
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "formfile err: "+err.Error())
		c.AbortWithStatusJSON(400, gin.H{"error": err.Error()})
		return
	}

	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.UploadProfileImage(c.Request.Context(), *currentUser, fileHeader)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Update user profile
// @Description Update a user's username and/or bio
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "profile update successful"
// @Failure 409 {object} errorHelper.ServiceError "username has ben taken"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.EditProfileDto true "edit profile request body"
// @Router /auth/edit-profile [post]
func (h HttpHandler) EditProfile(c *gin.Context) {
	body := dto.EditProfileDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding edit profile request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.EditProfile(c.Request.Context(), *currentUser, body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary change user password
// @Description Change a user's password
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "password change successful"
// @Failure 409 {object} errorHelper.ServiceError "incorrect current password"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.ChangePasswordDto true "change password request body"
// @Router /auth/change-password [post]
func (h HttpHandler) ChangePassword(c *gin.Context) {
	body := dto.ChangePasswordDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding edit profile request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.ChangePassword(c.Request.Context(), *currentUser, body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary change user type to agent
// @Description Switch a user to an agent
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "swtitching user to an agent successful"
// @Failure 400 {object} errorHelper.ServiceError "invalid BVN or BVN does not belong to user"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Param requestBody body dto.SwitchToAgentDto true "change password request body"
// @Router /auth/switch-to-agent-account [post]
func (h HttpHandler) SwitchToAgentAccount(c *gin.Context) {
	body := dto.SwitchToAgentDto{}
	if err := c.BindJSON(&body); err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "binding edit profile request body: "+err.Error())
		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			errFields := []string{}
			for _, valErr := range validationErrs {
				errFields = append(errFields, valErr.Field())
			}

			c.AbortWithStatusJSON(400, gin.H{"error": "invalid input in fields: " + strings.Join(errFields, ",")})
			return
		}

		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.SwitchToAgentAccount(c.Request.Context(), *currentUser, body)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Rate user
// @Description Drop a star rating for a user
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {object} interface{} "successfully rated user"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Router /auth/rate-user/{user_reference}/{rating} [get]
func (h HttpHandler) RateUser(c *gin.Context) {
	userReference := c.Param("user_reference")
	rating := c.Param("rating")
	// get user from jwt-token
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.RateUser(c.Request.Context(), *currentUser, userReference, rating)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Delete Account
// @Description Delete A Users Account and Clear out their data from the database
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {string} interface{} "User account deleted successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Failure 404 {object} errorHelper.ServiceError "user doesn't exist"
// @Router /auth/delete-account [get]
func (h HttpHandler) DeleteAccount(c *gin.Context) {
	currentUser, _ := tokenHelper.ValidateToken(c.GetHeader("Token"))

	response, err := h.httpPort.DeleteAccount(c.Request.Context(), *currentUser)
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}

// @Summary Logout
// @Description Unauthnticate a user
// @Tags User
// @Accept json
// @Produce json
// @Param Token header string true "Authentication token"
// @Success 200 {string} interface{} "Logout successfully"
// @Failure 500 {object} errorHelper.ServiceError "something went wrong"
// @Failure 404 {object} errorHelper.ServiceError "user doesn't exist"
// @Router /auth/logout [get]
func (h HttpHandler) Logout(c *gin.Context) {
	response, err := h.httpPort.Logout(c.GetHeader("Token"))
	if err != nil {
		c.AbortWithStatusJSON(err.(errorHelper.ServiceError).Code, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, response)
}
