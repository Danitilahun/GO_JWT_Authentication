package middleware

import (
	"github.com/Danitilahun/GO_JWT_Authentication.git/helper"
	"github.com/gin-gonic/gin"
	"net/http"
)

func getTokenFromHeader(c *gin.Context) string {
	// Extract token from the request header
	clientToken := c.Request.Header.Get("token")

	// Check if the token is empty
	if clientToken == "" {
		// Respond with an error indicating missing authorization header
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No Authorization header provided"})

		// Abort further processing
		c.Abort()
		return ""
	}

	return clientToken
}

func Authenticate() gin.HandlerFunc {

	return func(c *gin.Context) {

		// Extract token from the request header
		clientToken := getTokenFromHeader(c)

		// Validate the token
		claims, err := helper.ValidateToken(clientToken)

		// Check if there was an error validating the token
		if err != "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			c.Abort()
			return
		}

		// Set the claims in the context
		c.Set("email", claims.Email)
		c.Set("first_name", claims.First_name)
		c.Set("last_name", claims.Last_name)
		c.Set("uid", claims.Uid)
		c.Set("user_type", claims.User_type)

		c.Next()
	}
}
