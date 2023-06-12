package auth

import (
	"fmt"
	"time"

	"github.com/ardimr/go-authentication-service.git/internal/model"

	"github.com/golang-jwt/jwt"
)

type MyClaims struct {
	jwt.StandardClaims
	Username string `json:"Username"`
	Email    string `json:"Email"`
}

type Authentication interface {
	// Authenticate(reqUser *model.User, user *model.User)
	GenerateNewToken(user *model.UserInfo) (string, error)
	ValidateToken(tokenString string) (*jwt.Token, error)
	CheckPermission(userRolePermission model.RolePermission, resource string, action string) bool
}

type AuthService struct {
	Issuer     string
	ExpiresAt  int64
	SigningKey []byte
}

func NewAuthService(issuer string, expiresAt int64, signingKey []byte) *AuthService {
	return &AuthService{
		Issuer:     issuer,
		ExpiresAt:  expiresAt,
		SigningKey: signingKey,
	}
}

func (auth *AuthService) GenerateNewToken(user *model.UserInfo) (string, error) {
	// log.Println("Exp: ", auth.ExpiresAt)
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    auth.Issuer,
			ExpiresAt: time.Now().Add(time.Duration(auth.ExpiresAt) * time.Second).Unix(),
		},
		Username: user.Username,
		Email:    user.Email,
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	signedToken, err := token.SignedString(auth.SigningKey)

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (auth *AuthService) ValidateToken(tokenString string) (*jwt.Token, error) {
	mySigningKey := auth.SigningKey

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return mySigningKey, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil

}

func (auth *AuthService) CheckPermission(userRolePermission model.RolePermission, resource string, action string) bool {

	for _, rolePermission := range userRolePermission.Permissions {
		if rolePermission.ResourceName == resource {
			for _, actionPermitted := range rolePermission.Actions {
				if actionPermitted == action {
					return true
				}
			}
		}
	}

	return false
}
