package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"nmapwebui/internal/config"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

func parseUserFromToken(cfg *config.Config, c *gin.Context) (*models.User, bool) {
	tokenStr := ""
	if cookie, err := c.Cookie("access_token"); err == nil {
		tokenStr = cookie
	} else {
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			tokenStr = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if tokenStr == "" {
		return nil, false
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cfg.SecretKey), nil
	})
	if err != nil || !token.Valid {
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false
	}

	subFloat, ok := claims["sub"].(float64)
	if !ok {
		return nil, false
	}
	userID := uint(subFloat)

	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil || !user.Active {
		return nil, false
	}
	return &user, true
}

func AuthOptional(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if user, ok := parseUserFromToken(cfg, c); ok {
			c.Set("user", *user)
		}
		c.Next()
	}
}

func AuthRequired(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := parseUserFromToken(cfg, c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "Unauthorized"})
			return
		}
		c.Set("user", *user)
		c.Next()
	}
}

func AdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "Unauthorized"})
			return
		}
		u := user.(models.User)
		if !u.IsAdmin() {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": "Admin access required"})
			return
		}
		c.Next()
	}
}

func CreateToken(cfg *config.Config, userID uint) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(cfg.TokenDuration()).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.SecretKey))
}
