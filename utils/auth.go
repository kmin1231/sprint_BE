package utils

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

func GetGoogleUserInfo(token *oauth2.Token) (map[string]interface{}, error) {
	client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to get user info, status: %d", resp.StatusCode)
		return nil, err
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}
