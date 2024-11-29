package main

import (
	"log"
	"strings"
	"strconv"
	"net/http"
	"time"
	"database/sql"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

const portNumber = ":3100" // to avoid port conflict

func main() {
	// loads configuration
	// config.LoadAuthConfig()
	// config.LoadDBConfig()

	InitDB()
	defer DB.Close()

	r := gin.Default()

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:6173"}, // React
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// r.GET("/auth/google", controllers.GoogleLogin)
	// r.GET("/auth/callback", controllers.GoogleCallback)

	// r.POST("/auth/refresh", controllers.RefreshToken)

	r.GET("/api/articles", FetchArticles)
	r.GET("/api/news/:article_id", GetArticle)


	// checks
	// if err := utils.CheckDBConnection(); err != nil {
	// 	log.Fatal("Database connection failed:", err)
	// }

	// log.Println("Database Connection Success!")

	if err := r.Run(portNumber); err != nil {
		log.Fatal("Failed to run server:", err)
	}
}


var DB *sql.DB

func InitDB() {
	var err error
	DB, err = sql.Open("sqlite3", "./testDB.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
}

func FetchArticles(c *gin.Context) {
	keyword := c.DefaultQuery("keyword", "")
	limit := c.DefaultQuery("limit", "5")

	limitInt, err := strconv.Atoi(limit)
	if err != nil || limitInt <= 0 {
		limitInt = 30
	}


	// count total number of articles
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM news2 WHERE Keywords LIKE ?"
	err = DB.QueryRow(countQuery, "%"+keyword+"%").Scan(&totalCount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// SQL query
	query := "SELECT * FROM news2 WHERE Keywords LIKE ? LIMIT ?"
	rows, err := DB.Query(query, "%"+keyword+"%", limitInt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var articles []map[string]interface{}
	for rows.Next() {
		var articleID, title, summary, source, url, keywords, date, imageURL string
		if err := rows.Scan(&articleID, &title, &summary, &source, &url, &keywords, &date, &imageURL); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	
		// date formatting
		dateParsed, err := time.Parse(time.RFC3339, date)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid date format"})
			return
		}
	
		keywordsArray := strings.Split(keywords, ",")
	
		articles = append(articles, gin.H{
			"article_id": articleID,
			"title":      title,
			"summary":    summary,
			"source":     source,
			"url":        url,
			"keywords":   keywordsArray,
			"date":       dateParsed.Format("2024-11-30"),
			"image_url":  imageURL,
		})
	}


	// response
	if len(articles) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"code":    200,
			"message": "No articles found",
			"keyword": keyword,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "Articles retrieved successfully.",
		"keyword": keyword,
		"total": totalCount,
		"articles": articles,
	})
}


func GetArticle(c *gin.Context) {
	articleID := c.Param("article_id")

	// query
	query := "SELECT * FROM news2 WHERE ID = ?"
	row := DB.QueryRow(query, articleID)

	var title, summary, source, url, keywords, date, imageURL string
	if err := row.Scan(&articleID, &title, &summary, &source, &url, &keywords, &date, &imageURL); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Article not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// date formatting
	dateParsed, err := time.Parse(time.RFC3339, date)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid date format"})
		return
	}

	// response
	c.JSON(http.StatusOK, gin.H{
		"code":     200,
		"message":  "Article retrieved successfully.",
		"article": gin.H{
			"article_id": articleID,
			"title":      title,
			"summary":    summary,
			"source":     source,
			"url":        url,
			"keywords":   keywords,
			"date":       dateParsed.Format("2024-11-30"),
			"image_url":  imageURL,
		},
	})
}
