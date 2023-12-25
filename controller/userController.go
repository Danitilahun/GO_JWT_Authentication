package controller

import (
	"github.com/Danitilahun/GO_JWT_Authentication.git/database"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"log"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "auth", "user")

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}
