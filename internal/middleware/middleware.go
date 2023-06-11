package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/ardimr/go-authentication-service.git/internal/auth"
	"github.com/ardimr/go-authentication-service.git/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func MiddlewareValidateToken(auth *auth.AuthService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Check the authorization header
		authHeader := ctx.GetHeader("Authorization")

		if len(authHeader) == 0 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Get token string in bearer
		tokenString := authHeader[len("Bearer "):]

		// Validate token
		token, err := auth.ValidateToken(tokenString)

		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Error": err.Error()})
			return
		}

		// Get token claims
		claims, ok := token.Claims.(jwt.MapClaims)

		if ok && token.Valid {
			// Put user data in the context as value
			ctx.Set("user-info", claims)
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{"Error": err.Error()})
			return
		}
	}
}

func UserHasPermission(auth *auth.AuthService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get User Info
		var userInfo model.UserInfo

		// Get action method
		action := ActionFromMethod(ctx.Request.Method)

		// Check permission
		user, ok := ctx.Get("user-info")

		userByte, _ := json.Marshal(user)

		err := json.Unmarshal(userByte, &userInfo)

		if err != nil {
			ctx.AbortWithStatusJSON(
				http.StatusBadRequest,
				gin.H{
					"Error": err.Error(),
				},
			)
			return
		}

		if !ok || !auth.CheckPermission(userInfo, action) {
			ctx.AbortWithStatusJSON(
				http.StatusForbidden,
				gin.H{
					"Message": "Forbidden Access",
				},
			)
			return
		}
	}
}

func ActionFromMethod(httpMethod string) string {
	switch httpMethod {
	case "GET":
		return "view"
	case "POST":
		return "add"
	case "DELETE":
		return "delete"
	case "PATCH":
		return "edit"
	default:
		return ""
	}
}
