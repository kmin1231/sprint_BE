package main

import (
	"log"

	"github.com/kmin1231/sprint_BE/config"
	"github.com/kmin1231/sprint_BE/controllers"
	"github.com/kmin1231/sprint_BE/utils"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

const portNumber = ":3100" // to avoid port conflict

func main() {
	// loads configuration
	config.LoadAuthConfig()
	config.LoadDBConfig()

	r := gin.Default()

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"}, // React
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	r.GET("/auth/google", controllers.GoogleLogin)
	r.GET("/auth/callback", controllers.GoogleCallback)

	r.POST("/auth/refresh", controllers.RefreshToken)

	// checks
	if err := utils.CheckDBConnection(); err != nil {
		log.Fatal("Database connection failed:", err)
	}

	log.Println("Database Connection Success!")

	if err := r.Run(portNumber); err != nil {
		log.Fatal("Failed to run server:", err)
	}
}
