package helper

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
