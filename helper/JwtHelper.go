package helper

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
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
