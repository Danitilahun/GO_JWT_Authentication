package route

import (
	"github.com/Danitilahun/GO_JWT_Authentication.git/controller"
	"github.com/Danitilahun/GO_JWT_Authentication.git/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
}
