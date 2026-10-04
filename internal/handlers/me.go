package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

func meResponse(u models.User) gin.H {
	return gin.H{
		"id": u.ID, "username": u.Username, "email": u.Email, "role": u.Role,
		"timezone": u.Timezone, "last_login": u.LastLogin, "created_at": u.CreatedAt,
	}
}

// GetMe returns the signed-in user's own profile.
func GetMe(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, meResponse(user.(models.User)))
}

type UpdateMeInput struct {
	Email           *string `json:"email"`
	Timezone        *string `json:"timezone"`
	CurrentPassword string  `json:"current_password"`
	NewPassword     string  `json:"new_password"`
}

// UpdateMe lets a user change their own email, timezone and password.
func UpdateMe(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)

	var input UpdateMeInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}
	updates := map[string]interface{}{}

	if input.Email != nil {
		email := strings.TrimSpace(*input.Email)
		if email == "" || !strings.Contains(email, "@") {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Enter a valid email address"})
			return
		}
		var count int64
		db.DB.Model(&models.User{}).Where("email = ? AND id <> ?", email, u.ID).Count(&count)
		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"detail": "That email is already in use"})
			return
		}
		updates["email"] = email
	}

	if input.Timezone != nil {
		tz := strings.TrimSpace(*input.Timezone)
		if tz == "" {
			tz = "UTC"
		}
		if _, err := time.LoadLocation(tz); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Unknown timezone: " + tz})
			return
		}
		updates["timezone"] = tz
	}

	if input.NewPassword != "" {
		if len(input.NewPassword) < 6 {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "New password must be at least 6 characters"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.CurrentPassword)) != nil {
			c.JSON(http.StatusForbidden, gin.H{"detail": "Current password is incorrect"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not hash password"})
			return
		}
		updates["password_hash"] = string(hash)
	}

	if len(updates) > 0 {
		if err := db.DB.Model(&u).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
			return
		}
	}
	db.DB.First(&u, u.ID)
	c.JSON(http.StatusOK, meResponse(u))
}
