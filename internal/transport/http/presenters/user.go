package presenters

type UserCreateWithRolesRequest struct {
	FirstName string   `json:"first_name" binding:"required" validate:"required,max=128"`
	LastName  string   `json:"last_name" binding:"required" validate:"required,max=128"`
	Email     string   `json:"email" binding:"required,email" validate:"required,email,max=128"`
	Password  string   `json:"password" binding:"required" validate:"required,min=8,max=40,password"`
	Roles     []string `json:"roles" binding:"required" validate:"required"`
}

type EmailConfirmationToken struct {
	UserID int
	Token  string
	Email  string
}

type UserUpdateRequest struct {
	FirstName  *string `json:"first_name" validate:"omitempty,max=128"`
	LastName   *string `json:"last_name" validate:"omitempty,max=128"`
	Email      *string `json:"email" validate:"email,omitempty,max=128"`
	Password   *string `json:"password" validate:"min=8,omitempty,max=40,password"`
	LocaleType *string `json:"locale_type" example:"ru-RU" validate:"omitempty"`
}

type UserUpdateAdminRequest struct {
	FirstName  *string   `json:"first_name" validate:"omitempty,max=128"`
	LastName   *string   `json:"last_name" validate:"omitempty,max=128"`
	Email      *string   `json:"email" validate:"email,omitempty,max=128"`
	Password   *string   `json:"password" validate:"min=8,omitempty,max=40,password"`
	LocaleType *string   `json:"locale_type" example:"ru-RU" validate:"omitempty"`
	Roles      *[]string `json:"roles" validate:"omitempty"`
}

type PasswordResetRequest struct {
	Email string `json:"email" binding:"required,email" validate:"required,email,max=128"`
}

type PasswordResetResponse struct {
	Message string `json:"message"`
}
type TokenResReq struct {
	AccessToken string `json:"access_token"`
}

type UserResponse struct {
	FirstName      string   `json:"first_name"`
	LastName       string   `json:"last_name"`
	Email          string   `json:"email"`
	EmailConfirmed bool     `json:"email_confirmed"`
	LocaleType     *string  `json:"locale_type"`
	Roles          []string `json:"roles"`
	Photo          *string  `json:"photo"`
}

type UserAdminResponse struct {
	ID             int      `json:"id"`
	FirstName      string   `json:"first_name"`
	LastName       string   `json:"last_name"`
	Email          string   `json:"email"`
	EmailConfirmed bool     `json:"email_confirmed"`
	LocaleType     *string  `json:"locale_type"`
	Roles          []string `json:"roles"`
	Photo          *string  `json:"photo"`
}

type UserListResponse struct {
	Items []UserResponse `json:"items"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Limit int            `json:"limit"`
}

type UserAdminListResponse struct {
	Items []UserAdminResponse `json:"items"`
	Total int                 `json:"total"`
	Page  int                 `json:"page"`
	Limit int                 `json:"limit"`
}
