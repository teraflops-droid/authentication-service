package servers

import (
	"authentication/internal/controllers"
	"authentication/internal/middlewares"
	"authentication/pkg/service"
	"github.com/gin-gonic/gin"
	"net/http"
)

func NewRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	health := new(controllers.HealthController)

	var jwtService service.JWTService = service.JWTAuthService()

	var userController controllers.UserController = controllers.UserHandler(jwtService)
	router.GET("/health", health.Status)

	router.GET("/resource", gin.BasicAuth(gin.Accounts{
		"admin": "secret",
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"data": "resource data",
		})
	})

	//router.Use(middlewares.AuthMiddleware())

	v1 := router.Group("/v1")
	{
		anonymousGroup := v1.Group("/anonymous")
		{
			anonymousGroup.POST("/register", func(ctx *gin.Context) {
				userController.Register(ctx)
			})
			anonymousGroup.POST("/login", func(ctx *gin.Context) {
				userController.Login(ctx)
			})
		}
		userGroup := v1.Group("/user")
		userGroup.Use(middlewares.AuthorizeJWT())
		{
			userGroup.GET("/resource", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"data": "resource data",
				})
			})
		}
	}
	return router

}
