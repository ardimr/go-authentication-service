package auth

import (
	"fmt"
	"log"
	"time"

	"github.com/ardimr/go-authentication-service.git/internal/model"

	"github.com/golang-jwt/jwt"
)

type MyClaims struct {
	jwt.StandardClaims
	Username string `json:"Username"`
	Email    string `json:"Email"`
	Role     string `json:"role"`
}
type Authentication interface {
	// Authenticate(reqUser *model.User, user *model.User)
	GenerateNewToken(user *model.User) (string, error)
	ValidateToken(tokenString string) (*jwt.Token, error)
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

// func Authenticate(c *gin.Context) {
// 	username, password, ok := c.Request.BasicAuth()

// 	if !ok {
// 		c.AbortWithError(http.StatusUnauthorized, errors.New("this is not basic auth"))
// 		return
// 	}

// 	// Get user from db

// 	if secret, ok := users[username]; !ok || secret != password {
// 		c.AbortWithError(http.StatusUnauthorized, errors.New("wrong username or password"))
// 		return
// 	}

// 	newToken, err := GenerateNewToken(username)

// 	if err != nil {
// 		fmt.Println(err.Error())
// 		c.AbortWithError(http.StatusInternalServerError, errors.New("failed to generate new token"))
// 	}

// 	// c.SetCookie("token", newToken, 60, "/", "localhost", false, true)
// 	c.JSON(http.StatusOK, gin.H{
// 		"token": newToken,
// 	})

// }

// func Authorize(c *gin.Context) {
// 	// Check the value of bearer in header
// 	authHeader := c.GetHeader("Authorization")
// 	tokenString := authHeader[len("Bearer "):]
// 	fmt.Println(tokenString)
// 	if len(authHeader) == 0 {
// 		c.AbortWithStatus(http.StatusUnauthorized)
// 	}

// 	token, err := ValidateToken(tokenString)

// 	if err != nil {
// 		fmt.Println(err.Error())
// 		c.AbortWithStatus(http.StatusUnauthorized)
// 		return
// 	}

// 	claims, ok := token.Claims.(jwt.MapClaims)

// 	if ok && token.Valid {
// 		fmt.Println(claims["Username"])
// 	} else {
// 		fmt.Println(err.Error())
// 		c.AbortWithStatus(http.StatusUnauthorized)

// 		return
// 	}
// 	c.JSON(http.StatusOK, claims)
// 	fmt.Println("Authorized:", claims)
// }

func (auth *AuthService) GenerateNewToken(user *model.User) (string, error) {
	log.Println("Exp: ", auth.ExpiresAt)
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    auth.Issuer,
			ExpiresAt: time.Now().Add(time.Duration(auth.ExpiresAt) * time.Second).Unix(),
		},
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
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
