package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"fmt"
	"time"


	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"github.com/joho/godotenv"
	"github.com/gin-contrib/cors"


	"strconv"
	// "database/sql"
	_ "github.com/mattn/go-sqlite3"
	"errors"
)



var (
	DB                 *gorm.DB
	GoogleOAuthConfig  *oauth2.Config
	OAuthStateString   string
)

type User struct {
	UserID        uint       `gorm:"primaryKey;autoIncrement"`
	Email         string     `gorm:"unique;not null"`
	Username      string     `gorm:"type:varchar(255);not null"`
	SavedArticles []News     `gorm:"many2many:user_articles;"`
}

type News struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	Title    string `gorm:"not null"`
	Keywords  string `json:"keywords"`
	Summary  string
	Source   string
	URL      string
	Date     string
	ImageURL string
}

func loadEnvVariables() {
    err := godotenv.Load()
    if err != nil {
        log.Fatalf("Error loading .env file: %v", err)
    }
}

func main() {
	loadEnvVariables()
	
	// Initialize Database
	initDatabase()

	// Load OAuth Config
	LoadAuthConfig()

	// Set up router
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:6173"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))


	router.GET("/auth/google", GoogleLogin)
	router.GET("/auth/callback", GoogleCallback)
	router.POST("/auth/refresh", RefreshToken)

	router.POST("/api/user/article", SaveArticle)
	router.GET("/api/user/:id/articles", GetSavedArticles)

	
	router.GET("/api/articles", FetchArticles)
	router.GET("/api/news/:article_id", GetArticle)


	router.GET("/api/testing", multiple)


	router.Run(":3100")
}

func initDatabase() {
	var err error
	DB, err = gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = DB.AutoMigrate(&User{}, &News{})
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}


func LoadAuthConfig() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Failed to load .env file!")
	}

	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")

	if clientID == "" || clientSecret == "" || redirectURL == "" {
		log.Fatal("Google OAuth configuration is missing!")
	}

	GoogleOAuthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	// GenerateRandomState()
	// log.Println("OAuthStateString set to:", OAuthStateString)
}

func GenerateRandomState() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal("Failed to generate random state:", err)
	}
	return hex.EncodeToString(bytes)
}

func GoogleLogin(c *gin.Context) {
	url := GoogleOAuthConfig.AuthCodeURL(OAuthStateString, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusFound, url)
}


func GoogleCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")

	// state := ""

	storedState, exists := c.Get("oauth_state") 

	log.Println("storedState:", storedState)
	log.Println("exists:", exists)


	// storedState, exists := c.Get("oauth_state")
	// if !exists || state != storedState.(string) {
	// 	log.Println("Invalid state")
	// 	c.JSON(http.StatusBadRequest, gin.H{
	// 	  "message": "Invalid OAuth state",
	// 	})
	// 	return
	//   }


	
	log.Println("state:", state)
	log.Println("code:", code)

	// if state != OAuthStateString {
	// 	log.Println("Invalid OAuth state")
		// if err != nil {
		// 	log.Println("ERROR:", err)
		// 	}
		// 	return
		// }
		// c.JSON(http.StatusBadRequest, gin.H{
		// 	"message": "Invalid OAuth state",
		// })
		// return
	OAuthStateString := state
	log.Println("OAuthStateString:", OAuthStateString)


	token, err := GoogleOAuthConfig.Exchange(c, code)
	if err != nil {
		log.Println("Failed to exchange token:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to exchange token",
		})
		return
	}

	userInfo, err := GetGoogleUserInfo(token)
	if err != nil {
		log.Println("Failed to get user info:", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to get user info",
		})
		return
	}

	email := userInfo["email"].(string)

	user, err := SaveUserToDatabase(email, userInfo)
	if err != nil {
		fmt.Println("Error saving user:", err)
		return
	}
	fmt.Println("User saved:", user.Username)

	c.JSON(http.StatusOK, gin.H{
		"user_info": gin.H{
			"id":    userInfo["id"],
			"email": userInfo["email"],
			"name":  strings.Split(userInfo["email"].(string), "@")[0],
		},
		"access_token": token.AccessToken,
		"expires_in":   int(token.Expiry.Sub(time.Now()).Seconds()),
		"token_type":   token.TokenType,
	})

	c.Redirect(http.StatusFound, "http://localhost:6173/main")
}






func GetGoogleUserInfo(token *oauth2.Token) (map[string]interface{}, error) {
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))
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


func SaveUserToDatabase(email string, userInfo map[string]interface{}) (*User, error) {
	username := strings.Split(email, "@")[0]
	user := User{
		Email:    email,
		Username: username,
	}

	result := DB.FirstOrCreate(&user, User{Email: email})
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

func FetchUser(email string) (*User, error) {
	username := strings.Split(email, "@")[0]
	user := User{
		Email:    email,
		Username: username,
	}

	result := DB.FirstOrCreate(&user, User{Email: email})
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

func SaveArticle(c *gin.Context) {
	var input struct {
		ArticleID uint `json:"article_id"`
	}

	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Authorization token is missing"})
		return
	}

	tokenString = tokenString[len("Bearer "):]

	userInfo, err := VerifyGoogleAccessToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid or expired token"})
		return
	}

	userID := userInfo["user_id"].(uint)

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "Invalid input"})
		return
	}

	var article News
	if err := DB.First(&article, input.ArticleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "Article not found"})
		return
	}

	var user User
	if err := DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "User not found"})
		return
	}

	if err := DB.Model(&user).Association("SavedArticles").Append(&article); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "Failed to save article"})
		return
	}

	keywordsArray := strings.Split(article.Keywords, ",")

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "Article saved successfully.",
		"article": gin.H{
			"article_id": article.ID,
			"title":      article.Title,
			"summary":    article.Summary,
			"source":     article.Source,
			"url":        article.URL,
			"keywords":   keywordsArray,
			"date":       article.Date,
			"image_url":  article.ImageURL,
		},
	})
}




func VerifyGoogleAccessToken(tokenString string) (map[string]interface{}, error) {
	client := &http.Client{}
	url := fmt.Sprintf("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=%s", tokenString)

	resp, err := client.Get(url)
	if err != nil {
		log.Println("Error verifying token:", err)
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Invalid or expired token")
	}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result); err != nil {
		log.Println("Error decoding response:", err)
		return nil, err
	}

	userInfo := map[string]interface{}{
		"user_id": result["sub"],
		"email":   result["email"],
		"name":    result["name"],
	}

	return userInfo, nil
}


func GetSavedArticles(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Authorization token is missing"})
		return
	}

	tokenString = tokenString[len("Bearer "):]

	userInfo, err := VerifyGoogleAccessToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid or expired token"})
		return
	}

	tokenUserID := userInfo["user_id"].(uint)

	var user User
	if err := DB.First(&user, tokenUserID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "User not found"})
		return
	}

	var savedArticles []News
	if err := DB.Model(&user).Association("SavedArticles").Find(&savedArticles); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "Failed to retrieve saved articles"})
		return
	}

	var responseArticles []gin.H
	for _, article := range savedArticles {
		// date formatting
		dateParsed, err := time.Parse("2024-11-30 12:34:56", article.Date)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "Invalid date format"})
			return
		}

		keywordsArray := strings.Split(article.Keywords, ",")

		responseArticles = append(responseArticles, gin.H{
			"article_id": article.ID,
			"title":      article.Title,
			"summary":    article.Summary,
			"source":     article.Source,
			"url":        article.URL,
			"keywords":   keywordsArray,
			"date":       dateParsed.Format("2024-11-30"),
			"image_url":  article.ImageURL,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"code":      200,
		"message":   "Saved articles retrieved successfully.",
		"user_id":   tokenUserID,
		"articles":  responseArticles,
	})
}



func RefreshToken(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	token, err := RefreshAccessToken(refreshToken)
	if err != nil {
		log.Println("Failed to refresh token:", err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "Failed to refresh token.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"message": "Token refreshed successfully.",
		"login_data": gin.H{
			"access_token": token.AccessToken,
			"expires_in":   int(token.Expiry.Sub(time.Now()).Seconds()),
			"token_type":   token.TokenType,
	}})
}


func RefreshAccessToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	newToken, err := GoogleOAuthConfig.TokenSource(context.Background(), token).Token()

	if err != nil {
		log.Println("Failed to refresh access token:", err)
		return nil, err
	}

	return newToken, nil
}







type News2 struct {
	ID       uint      `gorm:"primaryKey"`
	Title    string
	Summary  string
	Source   string
	URL      string
	Keywords string
	Date	string
	// Date     time.Time
	ImageURL string
}

func (News2) TableName() string {
	return "news2"
}



func FetchArticles(c *gin.Context) {
	keyword := c.DefaultQuery("keyword", "")
	limit := c.DefaultQuery("limit", "20")

	limitInt, err := strconv.Atoi(limit)
	if err != nil || limitInt <= 0 {
		limitInt = 30
	}

	var totalCount int64
	err = DB.Model(&News2{}).Where("Keywords LIKE ?", "%"+keyword+"%").Count(&totalCount).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var articles []News2
	err = DB.Where("Keywords LIKE ?", "%"+keyword+"%").Limit(limitInt).Find(&articles).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	responseArticles := make([]map[string]interface{}, 0, len(articles))
	for _, article := range articles {
		keywordsArray := strings.Split(article.Keywords, ",")
		dateFormatted := article.Date
		responseArticles = append(responseArticles, gin.H{
			"article_id": article.ID,
			"title":      article.Title,
			"summary":    article.Summary,
			"source":     article.Source,
			"url":        article.URL,
			"keywords":   keywordsArray,
			"date":       dateFormatted,
			"image_url":  article.ImageURL,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"code":     200,
		"message":  "Articles retrieved successfully.",
		"keyword":  keyword,
		"total":    totalCount,
		"articles": responseArticles,
	})
}



func GetArticle(c *gin.Context) {
	articleID := c.Param("article_id")

	var article News2
	err := DB.First(&article, "id = ?", articleID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Article not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	keywordsArray := strings.Split(article.Keywords, ",")
	dateFormatted := article.Date

	c.JSON(http.StatusOK, gin.H{
		"article_id": article.ID,
		"title":      article.Title,
		"summary":    article.Summary,
		"source":     article.Source,
		"url":        article.URL,
		"keywords":   keywordsArray,
		"date":       dateFormatted,
		"image_url":  article.ImageURL,
	})
}



func multiple(c *gin.Context) {
	keywords := c.DefaultQuery("keywords", "")
	limit := c.DefaultQuery("limit", "20")

	limitInt, err := strconv.Atoi(limit)
	if err != nil || limitInt <= 0 {
		limitInt = 30
	}

	keywordList := strings.Split(keywords, ",")
	
	var conditions []string
	var args []interface{}

	for _, keyword := range keywordList {
		conditions = append(conditions, "Keywords LIKE ?")
		args = append(args, "%"+strings.TrimSpace(keyword)+"%")
	}

	var totalCount int64
	err = DB.Model(&News2{}).Where(strings.Join(conditions, " OR "), args...).Distinct("ID").Count(&totalCount).Error
	// err = DB.Model(&News2{}).Where(strings.Join(conditions, " OR "), args...).Count(&totalCount).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var articles []News2
	err = DB.Where(strings.Join(conditions, " OR "), args...).Limit(limitInt).Find(&articles).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	responseArticles := make([]map[string]interface{}, 0, len(articles))
	for _, article := range articles {
		keywordsArray := strings.Split(article.Keywords, ",")
		dateFormatted := article.Date
		responseArticles = append(responseArticles, gin.H{
			"article_id": article.ID,
			"title":      article.Title,
			"summary":    article.Summary,
			"source":     article.Source,
			"url":        article.URL,
			"keywords":   keywordsArray,
			"date":       dateFormatted,
			"image_url":  article.ImageURL,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"code":     200,
		"message":  "Articles retrieved successfully.",
		"keywords": keywords,
		"total":    totalCount,
		"articles": responseArticles,
	})
}
