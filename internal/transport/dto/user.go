package dto

type UserCreateWithRolesRequest struct {
	FirstName string   `validate:"required,max=128"`
	LastName  string   `validate:"required,max=128"`
	Email     string   `validate:"required,email,max=128"`
	Password  string   `validate:"required,min=8,max=40,password"`
	Roles     []string `validate:"required"`
}

type UserUpdateRequest struct {
	FirstName  *string `validate:"omitempty,max=128"`
	LastName   *string `validate:"omitempty,max=128"`
	Email      *string `validate:"omitempty,email,max=128"`
	Password   *string `validate:"omitempty,min=8,max=40,password"`
	LocaleType *string `example:"ru-RU" validate:"omitempty"`
}

type UserUpdateAdminRequest struct {
	FirstName  *string   `validate:"omitempty,max=128"`
	LastName   *string   `validate:"omitempty,max=128"`
	Email      *string   `validate:"omitempty,email,max=128"`
	Password   *string   `validate:"omitempty,min=8,max=40,password"`
	LocaleType *string   `example:"ru-RU" validate:"omitempty"`
	Roles      *[]string `validate:"omitempty"`
}

type PasswordResetRequest struct {
	Email string `validate:"required,email,max=128"`
}
