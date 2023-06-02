package router

import (
	"github.com/ardimr/go-authentication-service.git/internal/auth"
	"github.com/ardimr/go-authentication-service.git/internal/controller"
	"github.com/ardimr/go-authentication-service.git/internal/middleware"

	"github.com/gin-gonic/gin"
)

type Router struct {
	controller *controller.Controller
	auth       *auth.AuthService
}

func NewRouter(controller *controller.Controller, auth *auth.AuthService) *Router {
	return &Router{
		controller: controller,
		auth:       auth,
	}
}

func (router *Router) AddRoute(superRoute *gin.RouterGroup) {
	router.AddUserRoutes(superRoute)
	router.AddAuthRoutes(superRoute)
}

func (router *Router) AddAuthRoutes(superRoute *gin.RouterGroup) {
	authRouter := superRoute.Group("/auth")
	authRouter.POST("/login", router.controller.SignIn)

}

func (router *Router) AddUserRoutes(superRoute *gin.RouterGroup) {
	userRouter := superRoute.Group("/user-management")
	userRouter.Use(middleware.MiddlewareValidateToken(router.auth))
	userRouter.Use(middleware.UserHasPermission(router.auth))

	userRouter.GET("/users", router.controller.GetUsers)
	userRouter.GET("/users/:id", router.controller.GetUserById)
	userRouter.POST("/users", router.controller.AddNewUser)
	userRouter.PATCH("/users", router.controller.UpdateUser)
	userRouter.DELETE("/users/:id", router.controller.DeleteUser)

}
