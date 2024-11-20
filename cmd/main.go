package main

import (
	"log"

	"github.com/kmin1231/sprint_BE/config"
	"github.com/kmin1231/sprint_BE/controllers"

	"github.com/gin-gonic/gin"
)

const portNumber = ":3000"

func main() {
	config.LoadAuthConfig()

	r := gin.Default()

	r.GET("/auth/google", controllers.GoogleLogin)
	r.GET("/auth/callback", controllers.GoogleCallback)

	if err := r.Run(":3000"); err != nil {
		log.Fatal("Failed to run server:", err)
	}
}
