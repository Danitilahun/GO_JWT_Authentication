package helper

import "github.com/dgrijalva/jwt-go"

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
