package presenters

type UserLoginRequest struct {
	Login    string `json:"login" binding:"required" validate:"required,max=128"`
	Password string `json:"password" binding:"required" validate:"required,min=8,max=40,password"`
}

type UserRegisterRequest struct {
	FirstName string `json:"first_name" binding:"required" validate:"required,max=128"`
	LastName  string `json:"last_name" binding:"required" validate:"required,max=128"`
	Email     string `json:"email" binding:"required,email" validate:"required,email,max=128"`
	Password  string `json:"password" binding:"required" validate:"required,min=8,max=40,password"`
}
