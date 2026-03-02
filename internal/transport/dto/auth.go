package dto

type LoginRequest struct {
	Login    string `validate:"required,max=128"`
	Password string `validate:"required,min=8,max=40,password"`
}

type RegisterRequest struct {
	FirstName string `validate:"required,max=128"`
	LastName  string `validate:"required,max=128"`
	Email     string `validate:"required,email,max=128"`
	Password  string `validate:"required,min=8,max=40,password"`
}
