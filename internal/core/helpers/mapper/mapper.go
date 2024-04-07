package helpers

import (
	"fmt"
	"realtz-user-service/internal/core/domain/dto"
	"realtz-user-service/internal/core/domain/entity"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func CreateUserFromSignupDto(signupDto dto.SignupDto) entity.User {
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte(signupDto.Password), bcrypt.DefaultCost)
	return entity.User{
		Reference:     uuid.New().String(),
		UserType:      signupDto.UserType,
		Firstname:     signupDto.Firstname,
		Lastname:      signupDto.Lastname,
		Fullname:      fmt.Sprintf("%s %s", signupDto.Firstname, signupDto.Lastname),
		Username:      signupDto.Username,
		Email:         signupDto.Email,
		PhoneNumber:   ConvertPhoneToInternationalFormat(signupDto.PhoneNumber),
		StarRating:    1,
		RatedBy:       []string{},
		Password:      string(passwordHash),
		IsActive:      true,
		CreatedOn:     time.Now().Format(time.RFC3339),
		LastUpdatedOn: time.Now().Format(time.RFC3339),
	}
}

func ConvertPhoneToInternationalFormat(phone string) string {
	return "+234" + phone[1:]
}
