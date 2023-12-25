package controller

import (
	"github.com/Danitilahun/GO_JWT_Authentication.git/database"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "auth", "user")
