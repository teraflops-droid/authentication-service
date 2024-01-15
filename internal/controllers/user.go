package controllers

import (
	"authentication/pkg/models"
	"authentication/pkg/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

type UserController interface {
	Register(ctx *gin.Context)
	Login(ctx *gin.Context)
}

type userController struct {
	jwtService service.JWTService
	users      []models.User
}

func UserHandler(jWtService service.JWTService) UserController {
	return &userController{
		jwtService: jWtService,
	}
}

func (u *userController) Register(c *gin.Context) {
	var requestBody models.User
	if err := c.BindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Missing required field(s)."})
		c.Abort()
		return
	}
	if requestBody.Email == "" || requestBody.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Missing required field(s)."})
		c.Abort()
		return
	}
	user := models.User{Email: requestBody.Email, Password: requestBody.Password}
	for _, data := range u.users {
		if data.Email == user.Email {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Duplicate email."})
			c.Abort()
			return
		}
	}
	u.users = append(u.users, user)
	fmt.Printf("len=%d cap=%d %v\n", len(u.users), cap(u.users), u.users)
	c.JSON(http.StatusCreated, gin.H{"message": "Registered successfully.", "data": user})
	return
}

func (u *userController) Login(c *gin.Context) {
	var requestBody models.User
	if err := c.BindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Missing required field(s)."})
		c.Abort()
		return
	}
	if requestBody.Email == "" || requestBody.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Missing required field(s)."})
		c.Abort()
		return
	}

	for _, data := range u.users {
		if data.Email == requestBody.Email {
			token, refreshToken, err := u.jwtService.GenerateTokens(requestBody.Email, true)
			if err != nil {
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"message": "Logged in successfully",
				"data": gin.H{
					"accessToken":  token,
					"refreshToken": refreshToken}})
			return
		}
	}
	c.JSON(http.StatusBadRequest, gin.H{"message": "No matches credential."})
	c.Abort()
	return
}
