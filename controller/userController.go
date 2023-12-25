package controller

import (
	"github.com/Danitilahun/GO_JWT_Authentication.git/database"
	"github.com/Danitilahun/GO_JWT_Authentication.git/helper"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "auth", "user")
