package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ardimr/go-authentication-service.git/internal/model"
	"github.com/ardimr/go-authentication-service.git/internal/query"
	"github.com/gin-gonic/gin"

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
	Querier    query.Querier
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

func NewAuthService(issuer string, expiresAt int64, signingKey []byte, querier query.Querier) *AuthService {
	return &AuthService{
		Issuer:     issuer,
		ExpiresAt:  expiresAt,
		SigningKey: signingKey,
		Querier:    querier,
	}
}

func (auth *AuthService) SignIn(ctx *gin.Context) {
	// Get username and password as the basic auth
	username, password, ok := ctx.Request.BasicAuth()

	if !ok {
		ctx.AbortWithStatus(http.StatusBadRequest)
		log.Println("Not a basic auth")
		return
	}

	// Get user's info
	user, err := auth.Querier.GetUserInfoByUsername(ctx, username)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			ctx.JSON(http.StatusUnauthorized, gin.H{"Error": "User not found"})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
		}
		return
	}

	// Check if the userPassword is correct
	if user.Password != password {
		log.Println(user.Password, password)
		ctx.JSON(http.StatusUnauthorized, gin.H{"Error": "Incorrect Password"})
		return
	}

	// User is authenticated, proceed to generate new token
	newTokenPair, err := auth.GenerateNewTokenPair(user)

	if err != nil {
		fmt.Println(err.Error())
		ctx.AbortWithError(http.StatusInternalServerError, errors.New("failed to generate new token"))
	}

	// c.SetCookie("token", newToken, 60, "/", "localhost", false, true)
	ctx.JSON(http.StatusOK, gin.H{
		"access token":  newTokenPair.AccessToken,
		"refresh token": newTokenPair.RefreshToken,
	})
}

func (auth *AuthService) RefreshToken(ctx *gin.Context) {
	// Validate the refresh token

	// Generate new token pair
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

func (auth *AuthService) GenerateNewTokenPair(user *model.UserInfo) (TokenPair, error) {
	var tokenPair TokenPair
	// log.Println("Exp: ", auth.ExpiresAt)
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    auth.Issuer,
			ExpiresAt: time.Now().Add(time.Duration(auth.ExpiresAt) * time.Second).Unix(),
		},
		Username: user.Username,
		Email:    user.Email,
	}

	accessToken := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	signedAccessToken, err := accessToken.SignedString(auth.SigningKey)

	if err != nil {
		return tokenPair, err
	}

	refreshClaims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    auth.Issuer,
			ExpiresAt: time.Now().Add(time.Duration(auth.ExpiresAt) * time.Second).Unix(),
		},
		Username: user.Username,
	}

	refreshToken := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		refreshClaims,
	)
	signedRefreshToken, err := refreshToken.SignedString(auth.SigningKey)

	if err != nil {
		return tokenPair, err
	}

	tokenPair.AccessToken = signedAccessToken
	tokenPair.RefreshToken = signedRefreshToken

	return tokenPair, nil
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
