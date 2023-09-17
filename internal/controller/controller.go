package controller

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/ardimr/go-authentication-service.git/internal/auth"
	"github.com/ardimr/go-authentication-service.git/internal/model"
	"github.com/ardimr/go-authentication-service.git/internal/query"

	"github.com/gin-gonic/gin"
)

type Controller struct {
	querier query.Querier
	auth    auth.Authentication
}

func NewController(q query.Querier, auth auth.Authentication) *Controller {
	return &Controller{
		querier: q,
		auth:    auth,
	}
}

// Controller Implementation

// func (controller *Controller) SignIn(ctx *gin.Context) {
// 	// Get username and password as the basic auth
// 	username, password, ok := ctx.Request.BasicAuth()

// 	if !ok {
// 		ctx.AbortWithStatus(http.StatusBadRequest)
// 		log.Println("Not a basic auth")
// 		return
// 	}

// 	// Get user's info
// 	user, err := controller.querier.GetUserInfoByUsername(ctx, username)
// 	if err != nil {
// 		switch err {
// 		case sql.ErrNoRows:
// 			ctx.JSON(http.StatusUnauthorized, gin.H{"Error": "User not found"})
// 		default:
// 			ctx.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
// 		}
// 		return
// 	}

// 	// Check if the userPassword is correct
// 	if user.Password != password {
// 		log.Println(user.Password, password)
// 		ctx.JSON(http.StatusUnauthorized, gin.H{"Error": "Incorrect Password"})
// 		return
// 	}

// 	// User is authenticated, proceed to generate new token
// 	newToken, err := controller.auth.GenerateNewToken(user)

// 	if err != nil {
// 		fmt.Println(err.Error())
// 		ctx.AbortWithError(http.StatusInternalServerError, errors.New("failed to generate new token"))
// 	}

// 	// c.SetCookie("token", newToken, 60, "/", "localhost", false, true)
// 	ctx.JSON(http.StatusOK, gin.H{
// 		"token": newToken,
// 	})
// }

func (controller *Controller) SignUp(ctx *gin.Context) {
	// Get user info from sign up form
	var newUser model.NewUser
	if err := ctx.BindJSON(&newUser); err != nil {
		ctx.AbortWithStatusJSON(
			http.StatusBadRequest,
			gin.H{"Error": err.Error()},
		)
		return
	}

	// Generate hashed password
	hashedPassword, err := auth.HashPassword(newUser.Password)

	if err != nil {
		ctx.AbortWithStatusJSON(
			http.StatusInternalServerError,
			gin.H{"Error": err.Error()},
		)

		return
	}

	newUser.Password = hashedPassword

	// Add new user to the datasbase
	newId, err := controller.querier.AddNewUser(ctx, newUser)

	if err != nil {

		ctx.AbortWithStatusJSON(
			http.StatusInternalServerError,
			gin.H{"Error": err.Error()},
		)
		return
	}

	ctx.JSON(
		http.StatusOK,
		gin.H{"New Id": newId},
	)
}

func (controller *Controller) AddUserRole(ctx *gin.Context) {
	var newUserRole model.UserRole

	if err := ctx.BindJSON(&newUserRole); err != nil {
		ctx.AbortWithStatusJSON(
			http.StatusBadRequest,
			gin.H{"Error": err.Error()},
		)
		return
	}

	// Add user role to database
	newId, err := controller.querier.AddUserRole(ctx, newUserRole)

	if err != nil {
		ctx.AbortWithStatusJSON(
			http.StatusBadRequest,
			gin.H{"Error": err.Error()},
		)
		return
	}

	ctx.JSON(
		http.StatusOK,
		gin.H{"New ID": newId},
	)
}

func (controller *Controller) GetUsers(ctx *gin.Context) {

	// Get users data from db
	users, err := controller.querier.GetUsers(ctx)
	if err != nil {
		ctx.JSON(
			http.StatusInternalServerError,
			gin.H{
				"Message": err.Error(),
			},
		)
		return
	}

	ctx.JSON(
		http.StatusOK,
		users,
	)
}

func (controller *Controller) GetUserById(ctx *gin.Context) {
	var reqUri model.GetUserByIdReqUri

	// Request URI Binding
	if err := ctx.BindUri(&reqUri); err != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{
				"message": err.Error(),
			},
		)
		return
	}

	user, err := controller.querier.GetUserById(ctx, reqUri.ID)

	if err != nil {
		switch err {
		case sql.ErrNoRows:
			ctx.JSON(
				http.StatusNotFound,
				gin.H{
					"Message": "Not Found",
				},
			)
		}
		return
	}

	// Success state
	ctx.JSON(
		http.StatusOK,
		user,
	)
}

func (controler *Controller) AddNewUser(ctx *gin.Context) {
	var newUser model.NewUser

	if err := ctx.BindJSON(&newUser); err != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{
				"Message": err.Error(),
			},
		)
		return
	}

	newId, err := controler.querier.AddNewUser(ctx, newUser)

	if err != nil {
		ctx.JSON(
			http.StatusInternalServerError,
			gin.H{
				"Message": err.Error(),
			},
		)

		return
	}

	ctx.JSON(
		http.StatusOK,
		gin.H{
			"New Id": newId,
		},
	)
}

func (controller *Controller) UpdateUser(ctx *gin.Context) {
	var user model.User

	if err := ctx.BindJSON(&user); err != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{
				"Message": err.Error(),
			},
		)
		return
	}

	res, err := controller.querier.UpdateUser(ctx, user)

	if err != nil {
		ctx.JSON(
			http.StatusInternalServerError,
			gin.H{
				"Message": err.Error(),
			},
		)
		return
	}

	ctx.JSON(
		http.StatusOK,
		gin.H{
			"Rows affected": res,
		},
	)
}

func (controller *Controller) DeleteUser(ctx *gin.Context) {
	var reqUri model.DeleteUserReqUri

	if err := ctx.BindUri(&reqUri); err != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{
				"Message": err.Error(),
			},
		)
		return
	}

	if err := controller.querier.DeleteUser(ctx, reqUri.ID); err != nil {
		ctx.JSON(
			http.StatusInternalServerError,
			gin.H{
				"Message": err.Error(),
			},
		)
	}

	ctx.Status(
		http.StatusOK,
	)
}

func (controller *Controller) GetRolePermissions(ctx *gin.Context) {

	rolePermissions, err := controller.querier.GetRolePermissions(ctx)

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, rolePermissions)
}

func (controller *Controller) MiddlewareSetUserPermissions(ctx *gin.Context) {
	// Get user's info from the validated token
	var userInfo model.UserInfo
	user, ok := ctx.Get("user-info")

	if !ok {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

	userByte, _ := json.Marshal(user)
	err := json.Unmarshal(userByte, &userInfo)

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
	}

	// Get user's permission from the database
	rolePermissions, err := controller.querier.GetRolePermissionsByUsername(ctx, userInfo.Username)

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"Error": err.Error()})
	}

	// Attach user's permission on the header
	ctx.Set("user-permissions", rolePermissions)
}
