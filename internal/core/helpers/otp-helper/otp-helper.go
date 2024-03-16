package helpers

import (
	configHelper "realtz-user-service/internal/core/helpers/configuration-helper"
	errorHelper "realtz-user-service/internal/core/helpers/error-helper"
	logHelper "realtz-user-service/internal/core/helpers/log-helper"
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"
)

func GenerateOTP(acctName string) (string, string, error) {
	otpExpiry, _ := strconv.Atoi(configHelper.ServiceConfiguration.OtpExpiry)
	// Generate a new TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      configHelper.ServiceConfiguration.ServiceName,
		AccountName: acctName,
		Period:      uint(otpExpiry),
	})

	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "Error generating TOTP key: "+err.Error())
		return "", "", errorHelper.NewServiceError("something went wrong", 500)
	}

	// Generate and display the current TOTP
	otp, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		logHelper.LogEvent(logHelper.ErrorLog, "Error generating otp: "+err.Error())
		return "", "", errorHelper.NewServiceError("something went wrong", 500)
	}

	return otp, key.Secret(), nil
}

func ValidateOtp(otp, secret string) bool {
	return totp.Validate(otp, secret)
}
