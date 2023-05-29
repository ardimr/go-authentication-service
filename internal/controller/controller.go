package controller

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
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

func (controller *Controller) SignIn(ctx *gin.Context) {
	// Get username and password as the basic auth
	username, password, ok := ctx.Request.BasicAuth()

	if !ok {
		ctx.AbortWithStatus(http.StatusBadRequest)
		log.Println("Not a basic auth")
		return
	}

	// Get user's info
	user, err := controller.querier.GetUserByUsername(ctx, username)

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
		ctx.JSON(http.StatusUnauthorized, gin.H{"Error": "Incorrect Password"})
	}

	// User is authenticated, proceed to generate new token
	newToken, err := controller.auth.GenerateNewToken(user)

	if err != nil {
		fmt.Println(err.Error())
		ctx.AbortWithError(http.StatusInternalServerError, errors.New("failed to generate new token"))
	}

	// c.SetCookie("token", newToken, 60, "/", "localhost", false, true)
	ctx.JSON(http.StatusOK, gin.H{
		"token": newToken,
	})
}

func (controller *Controller) GetUsers(ctx *gin.Context) {

	userInfo, ok := ctx.Get("user-info")
	if ok {
		fmt.Println(userInfo)
	}

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
	var newUser model.User

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
