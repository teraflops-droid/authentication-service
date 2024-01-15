package middlewares

import (
	"authentication/pkg/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
)

func AuthorizeJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		const bearerSchema = "Bearer "
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			fmt.Println("Authorization header is missing")
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing."})
			c.Abort()
			//c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if len(authHeader) <= len(bearerSchema) {
			fmt.Println("Invalid token format")
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token format."})
			c.Abort()
			return
		}

		tokenString := authHeader[len(bearerSchema):]
		token, err := service.JWTAuthService().ValidateToken(tokenString)

		if err != nil {
			errMsg := fmt.Sprintf("%s", err)
			fmt.Println("Error validating token:", err)
			c.JSON(http.StatusUnauthorized, gin.H{"message": errMsg})
			c.Abort()
			return
		}

		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)
			fmt.Println("Token claims:", claims)
		} else {
			fmt.Println("Token is not valid")
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Token is not valid."})
			c.Abort()
		}
	}
}
