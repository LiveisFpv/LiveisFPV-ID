package validation

import (
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

func Init() {
	validate.RegisterValidation("password", PasswordValidator)
}
