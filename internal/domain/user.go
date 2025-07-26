package domain

type User struct {
	ID             int      `json:"user_id"`
	FirstName      string   `json:"first_name"`
	LastName       string   `json:"last_name"`
	Email          string   `json:"email"`
	EmailConfirmed bool     `json:"email_confirmed"`
	Password       *string  `json:"-"`
	GoogleID       *string  `json:"-"`
	YandexID       *string  `json:"-"`
	VkID           *string  `json:"-"`
	Photo          *string  `json:"photo"`
	Roles          []string `json:"roles"`
	LocaleType     *string  `json:"locale_type"`
}
