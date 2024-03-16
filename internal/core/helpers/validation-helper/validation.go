package helpers

import (
	"regexp"
	"strings"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

func InitBindingValidation() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("valid_phone_number", ValidNigerianPhoneNumber)
		v.RegisterValidation("valid_password", ValidateValidPassword)
	}
}

// EqualFieldValidation is a custom validation function
func ValidNigerianPhoneNumber(fl validator.FieldLevel) bool {
	fieldValue := fl.Field().String()

	phonePattern := `^0\d{10}$`

	return regexp.MustCompile(phonePattern).MatchString(fieldValue)
}

func ValidateValidPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	upperCasePattern := `[A-Z]+`
	lowerCasePattern := `[a-z]+`
	numPattern := `[0-9]+`
	symbolPattern :=  `[!@#$%^&*(”’)+,-./:;<=>?_^{}|~\\[\]\s]+`

	hasUppercase := regexp.MustCompile(upperCasePattern).MatchString(password)
	hasLowercase := regexp.MustCompile(lowerCasePattern).MatchString(password)
	hasNum := regexp.MustCompile(numPattern).MatchString(password)
	hasSymbol := regexp.MustCompile(symbolPattern).MatchString(password)

	return hasUppercase && hasLowercase && hasNum && hasSymbol && len(strings.TrimSpace(password)) >= 6
}
