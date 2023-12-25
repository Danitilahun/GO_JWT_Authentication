package helper

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Danitilahun/GO_JWT_Authentication.git/database"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// SignedDetails represents a structure combining user-specific details and standard JWT claims.
// It includes fields for Email, First_name, Last_name, Uid, and User_type
// to capture user information, along with jwt.StandardClaims for standard JWT metadata.
type SignedDetails struct {
	Email      string
	First_name string
	Last_name  string
	Uid        string
	User_type  string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "auth", "user")
var SECRET_KEY string = os.Getenv("SECRET_KEY")

// GenerateAllTokens generates JWT (JSON Web Token) and Refresh Token pair based on the provided user details.
// It creates a signed JWT containing user-specific claims (such as email, first name, last name, user type, UID)
// and sets an expiration time for both the JWT and Refresh Token.
// Parameters:
//
//	email: The email address of the user.
//	firstName: The first name of the user.
//	lastName: The last name of the user.
//	userType: The type of user (e.g., admin, regular user).
//	uid: The unique identifier for the user.
//
// Returns:
//
//	signedToken: The signed JWT representing the user's details with an expiration time of 24 hours.
//	signedRefreshToken: The signed Refresh Token with an expiration time of 7 days (168 hours).
//	err: Any error encountered during token generation.
func GenerateAllTokens(email string, firstName string, lastName string, userType string, uid string) (signedToken string, signedRefreshToken string, err error) {
	// Create JWT claims containing user-specific details and set expiration time for the access token
	claims := &SignedDetails{
		Email:      email,
		First_name: firstName,
		Last_name:  lastName,
		Uid:        uid,
		User_type:  userType,
		StandardClaims: jwt.StandardClaims{
			// Set expiration time for 24 hours from the current time
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	// Create claims for Refresh Token and set expiration time for 7 days
	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			// Set expiration time for 7 days from the current time
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}

	// Generate a signed JWT using HS256 signing method and the provided claims
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		// Handle error if token generation fails
		log.Panic(err)
		return
	}

	// Generate a signed Refresh Token using HS256 signing method and the refreshClaims
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		// Handle error if Refresh Token generation fails
		log.Panic(err)
		return
	}

	// Return the generated token pair and any error encountered (if applicable)
	return token, refreshToken, err
}

func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {

	// The jwt.ParseWithClaims function from the Go jwt library
	// is used to parse and validate a JWT (JSON Web Token) represented
	//  by the signedToken string against specific claims and with a provided key.

	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		msg = err.Error()
		return
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("the token is invalid")
		msg = err.Error()
		return
	}

	// Unix returns t as a Unix time, the number of seconds elapsed since January 1, 1970 UTC.
	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = fmt.Sprintf("token is expired")
		msg = err.Error()
		return
	}
	return claims, msg
}

// UpdateAllTokens updates the tokens and timestamp for a user identified by their user ID in the database.
// Parameters:
//
//	signedToken: The new signed JWT to be updated for the user.
//	signedRefreshToken: The new signed Refresh Token to be updated for the user.
//	userId: The unique identifier of the user whose tokens are to be updated.
func UpdateAllTokens(signedToken string, signedRefreshToken string, userId string) {
	// Create a context with a timeout of 100 seconds
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel() // Ensure context cancellation at the end of the function

	// Create a slice of primitive.E to store update operations
	var updateObj primitive.D

	// Append token and refresh token update operations to the updateObj
	updateObj = append(updateObj, bson.E{"token", signedToken})
	updateObj = append(updateObj, bson.E{"refresh_token", signedRefreshToken})

	// Get the current time and prepare an update operation for the 'updated_at' field
	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{"updated_at", Updated_at})

	// Prepare options for the update operation, set 'Upsert' to true to insert if the document does not exist
	upsert := true
	filter := bson.M{"user_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	// Perform the update operation on the userCollection
	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{"$set", updateObj}, // Use $set operator to update the specified fields
		},
		&opt,
	)

	// Ensure the context is cancelled regardless of the function's flow
	defer cancel()

	// Handle error if update operation fails
	if err != nil {
		log.Panic(err)
		return
	}

	// Return after successful token update
	return
}
