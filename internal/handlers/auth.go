package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"nmapwebui/internal/config"
	"nmapwebui/internal/db"
	"nmapwebui/internal/middleware"
	"nmapwebui/internal/models"
)

type LoginInput struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func Login(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input LoginInput
		if err := c.ShouldBind(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
			return
		}
		var user models.User
		if err := db.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"detail": "Incorrect username or password"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"detail": "Incorrect username or password"})
			return
		}
		if !user.Active {
			c.JSON(http.StatusForbidden, gin.H{"detail": "Account is deactivated"})
			return
		}

		token, err := middleware.CreateToken(cfg, user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
			return
		}

		c.SetCookie("access_token", token, cfg.AccessTokenExpireMin*60, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "bearer"})
	}
}

func Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.SetCookie("access_token", "", -1, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"detail": "Logged out"})
	}
}
