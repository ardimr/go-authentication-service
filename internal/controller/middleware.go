package controller

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func (controller *Controller) MiddlewareValidateToken(ctx *gin.Context) {
	// Check the authorization header
	authHeader := ctx.GetHeader("Authorization")

	if len(authHeader) == 0 {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	// Get token string in bearer
	tokenString := authHeader[len("Bearer "):]

	// Validate token
	token, err := controller.auth.ValidateToken(tokenString)

	if err != nil {
		log.Println(err.Error())
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Get token claims
	claims, ok := token.Claims.(jwt.MapClaims)

	if ok && token.Valid {
		// Put user data in the context as value
		ctx.Set("user-info", claims)
	} else {
		log.Println(err.Error())
		ctx.JSON(http.StatusUnauthorized, gin.H{"Error": err.Error()})
	}

}
