package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

func PasswordValidator(fl validator.FieldLevel) bool {
	pass := fl.Field().String()

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(pass)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(pass)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(pass)
	hasSymbol := regexp.MustCompile(`[!@#~$%^&*()+|_{}\[\]:;<>,.?/]`).MatchString(pass)

	return hasUpper && hasLower && hasNumber && hasSymbol
}
