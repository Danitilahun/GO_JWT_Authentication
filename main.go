package main

import (
	routes "github.com/Danitilahun/GO_JWT_Authentication.git/route"
	"github.com/gin-gonic/gin"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Gin is a lightweight web framework for the Go (or Golang) programming language.
	//  It helps developers build efficient and fast web applications and APIs by providing
	//  features like routing, middleware support, JSON handling, and graceful error management.
	router := gin.New()

	// use the default gin middleware for logging and recovery
	router.Use(gin.Logger())

	// use gin's built in error handling middleware for recovering from any panics
	// ( "panic" refers to a situation in which the program encounters an unexpected error that it cannot handle.
	// When a panic occurs in a Go program, it typically results in the program crashing and displaying an error
	//   message that includes a stack trace.)

	// By using gin.Recovery() as middleware in your Gin web application, you're making your server more robust
	// and resilient to unexpected errors. It helps to log information about the panic, recover from it, and
	// ensure that the server continues to serve requests, even in the presence of unexpected errors,
	// rather than crashing abruptly.

	router.Use(gin.Recovery())

	// define a simple route for testing
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to the API!",
		})
	})

	routes.AuthRoute(router)
	router.UserRoute(router)
	// start the server on port 8080
	router.Run(":" + port)
}
