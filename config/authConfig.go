package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var GoogleOAuthConfig *oauth2.Config
var OAuthStateString string

func LoadAuthConfig() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Failed to load .env file!")
	}

	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")

	if (clientID == "") || (clientSecret == "") || (redirectURL == "") {
		log.Fatal("Google OAuth configuration failed!")
	}

	GoogleOAuthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	OAuthStateString = "random_state_string"
}