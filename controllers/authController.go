package controllers

import (
	"log"
	"net/http"

	"github.com/kmin1231/sprint_BE/config"
	"github.com/kmin1231/sprint_BE/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func GoogleLogin(c *gin.Context) {
	url := config.GoogleOAuthConfig.AuthCodeURL(config.OAuthStateString, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusFound, url)
}

func GoogleCallback(c *gin.Context) {
	state := c.DefaultQuery("state", "")
	code := c.DefaultQuery("code", "")

	if state != config.OAuthStateString {
		log.Println("Invalid OAuth state")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	token, err := config.GoogleOAuthConfig.Exchange(c, code)
	if err != nil {
		log.Println("Failed to exchange token:", err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	userInfo, err := utils.GetGoogleUserInfo(token)
	if err != nil {
		log.Println("Failed to get user info:", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_info": userInfo,
	})
}
