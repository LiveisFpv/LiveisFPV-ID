package jwt

import (
	"authorization_service/internal/domain/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Creates new JWT token for given user, app
func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	//Add information to token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"uid":    user.ID,
			"email":  user.Email,
			"exp":    time.Now().Add(time.Hour * 24).Unix(), //!Есть проблема с парсом времени токен сразу протухает
			"app_id": app.ID,
		},
	)

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
