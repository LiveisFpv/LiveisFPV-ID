package validation

import (
	"github.com/go-playground/validator/v10"
)

var Valid = validator.New()

func Init() {
	Valid.RegisterValidation("password", PasswordValidator)
}
