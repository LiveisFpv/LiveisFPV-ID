package presenters

type UserLoginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UserRegisterRequest struct {
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required"`
}

type UserCreateWithRolesRequest struct {
	FirstName string   `json:"first_name" binding:"required"`
	LastName  string   `json:"last_name" binding:"required"`
	Email     string   `json:"email" binding:"required,email"`
	Password  string   `json:"password" binding:"required"`
	Roles     []string `json:"roles" binding:"required"`
}

type EmailConfirmationToken struct {
	UserID int
	Token  string
	Email  string
}
type UserUpdateRequest struct {
	FirstName  *string `json:"first_name"`
	LastName   *string `json:"last_name"`
	Email      *string `json:"email"`
	Password   *string `json:"password"`
	LocaleType *string `json:"locale_type" example:"ru-RU"`
}
type TokenResReq struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
