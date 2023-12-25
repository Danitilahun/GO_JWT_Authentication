package controller

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Danitilahun/GO_JWT_Authentication.git/database"
	helper "github.com/Danitilahun/GO_JWT_Authentication.git/helper"
	"github.com/Danitilahun/GO_JWT_Authentication.git/model"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "auth", "user")
var validate = validator.New()

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email of password is incorrect")
		check = false
	}
	return check, msg
}

// Signup returns a Gin handler function for user signup.
func Signup() gin.HandlerFunc {
	// Return an anonymous Gin handler function
	return func(c *gin.Context) {
		// Create a context with a timeout of 100 seconds
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel() // Ensure context cancellation at the end of the function

		var user models.User // Create a User model instance

		// Parse and bind the JSON request body to the user struct
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate the user struct using the validator
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		// Check if the email already exists in the database
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking for the email"})
			return
		}

		// Hash the user's password before saving it
		password := HashPassword(*user.Password)
		user.Password = &password

		// Check if the phone number already exists in the database
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking for the phone number"})
			return
		}

		// If email or phone already exists, return an error
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone number already exists"})
			return
		}

		// Set timestamps and generate unique identifiers for the user
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		// Generate JWT tokens for the user
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *&user.User_id)
		user.Token = &token
		user.Refresh_token = &refreshToken

		// Insert the user details into the database
		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		// Respond with a success status and the insertion result
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

// Login returns a Gin handler function for user login.
func Login() gin.HandlerFunc {
	// Return an anonymous Gin handler function
	return func(c *gin.Context) {
		// Create a context with a timeout of 100 seconds
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel() // Ensure context cancellation at the end of the function

		var user models.User      // Create a User model instance for incoming login details
		var foundUser models.User // Create a User model instance for the found user details

		// Parse and bind the JSON request body to the user struct
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Find the user in the database using their email
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			// If the user is not found or an error occurs, return an error response
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}

		// Verify the password provided with the stored hashed password
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordIsValid != true {
			// If the password verification fails, return an error response
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		// Check if the user is found based on the retrieved email
		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}

		// Generate JWT tokens for the authenticated user
		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)

		// Update user's tokens in the database
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)

		// Retrieve the updated user details from the database
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		if err != nil {
			// If an error occurs during fetching updated user details, return an error response
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Respond with the authenticated user's details
		c.JSON(http.StatusOK, foundUser)
	}
}
