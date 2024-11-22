package main

import (
	"log"

	"github.com/kmin1231/sprint_BE/config"
	"github.com/kmin1231/sprint_BE/controllers"
	"github.com/kmin1231/sprint_BE/utils"

	"github.com/gin-gonic/gin"
)

const portNumber = ":3000"

func main() {
	// loads configuration
	config.LoadAuthConfig()
	config.LoadDBConfig()

	r := gin.Default()

	r.GET("/auth/google", controllers.GoogleLogin)
	r.GET("/auth/callback", controllers.GoogleCallback)

	// checks
	if err := utils.CheckDBConnection(); err != nil {
		log.Fatal("Database connection failed:", err)
	}

	log.Println("Database Connection Success!")

	if err := r.Run(portNumber); err != nil {
		log.Fatal("Failed to run server:", err)
	}
}
