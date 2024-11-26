package config

import (
	"crypto/rand"
	"encoding/hex"
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

	// checks whether it works
	// log.Printf("CLIENT_ID: %s, CLIENT_SECRET: %s, REDIRECT_URL: %s", clientID, clientSecret, redirectURL)

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

	GenerateRandomState()
	log.Println("OAuthStateString set to:", OAuthStateString)
}

func GenerateRandomState() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal("Failed to generate random state:", err)
	}
	return hex.EncodeToString(bytes)
}
