package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

func ListUsers(c *gin.Context) {
	page, perPage := parsePagination(c)

	var total int64
	db.DB.Model(&models.User{}).Count(&total)

	var users []models.User
	db.DB.Order("id ASC").Offset(offset(page, perPage)).Limit(perPage).Find(&users)

	type SafeUser struct {
		ID       uint   `json:"ID"`
		Username string `json:"Username"`
		Email    string `json:"Email"`
		Role     string `json:"Role"`
		Active   bool   `json:"Active"`
	}
	var safe []SafeUser
	for _, u := range users {
		safe = append(safe, SafeUser{
			ID: u.ID, Username: u.Username, Email: u.Email,
			Role: u.Role, Active: u.Active,
		})
	}
	c.JSON(http.StatusOK, paginatedResponse(safe, total, page, perPage))
}

func GetStats(c *gin.Context) {
	var totalUsers, totalRuns, runningRuns int64
	db.DB.Model(&models.User{}).Count(&totalUsers)
	db.DB.Model(&models.ScanRun{}).Count(&totalRuns)
	db.DB.Model(&models.ScanRun{}).Where("status = ?", "running").Count(&runningRuns)
	c.JSON(http.StatusOK, gin.H{
		"total_users":       totalUsers,
		"total_scan_runs":   totalRuns,
		"running_scan_runs": runningRuns,
	})
}

type CreateUserInput struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role" binding:"required"`
}

func CreateUser(c *gin.Context) {
	caller, _ := c.Get("user")
	me := caller.(models.User)

	var input CreateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	// Role validation
	if input.Role != "user" && input.Role != "admin" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Role must be 'user' or 'admin'"})
		return
	}

	// Only superadmin can create admin users
	if input.Role == "admin" && !me.IsSuperAdmin() {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only superadmin can create admin users"})
		return
	}

	// Check uniqueness
	var existing models.User
	if db.DB.Where("username = ?", input.Username).First(&existing).Error == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Username already exists"})
		return
	}
	if db.DB.Where("email = ?", input.Email).First(&existing).Error == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Email already exists"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	user := models.User{
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: string(hash),
		Role:         input.Role,
		Active:       true,
		Timezone:     "UTC",
	}
	if err := db.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"ID": user.ID, "Username": user.Username,
		"Email": user.Email, "Role": user.Role, "Active": user.Active,
	})
}

type UpdateUserInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Active   *bool  `json:"active"`
}

func UpdateUser(c *gin.Context) {
	caller, _ := c.Get("user")
	me := caller.(models.User)
	id := c.Param("id")

	var target models.User
	if err := db.DB.First(&target, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "User not found"})
		return
	}

	// Cannot edit superadmin unless you are that superadmin
	if target.IsSuperAdmin() && me.ID != target.ID {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Cannot modify superadmin"})
		return
	}

	// Admin cannot edit other admins
	if target.IsAdmin() && !target.IsSuperAdmin() && !me.IsSuperAdmin() && me.ID != target.ID {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only superadmin can modify admin users"})
		return
	}

	var input UpdateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	updates := map[string]interface{}{}

	if input.Email != "" {
		var existing models.User
		if db.DB.Where("email = ? AND id != ?", input.Email, target.ID).First(&existing).Error == nil {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Email already exists"})
			return
		}
		updates["email"] = input.Email
	}

	if input.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		updates["password_hash"] = string(hash)
	}

	if input.Role != "" {
		// Cannot change superadmin's role
		if target.IsSuperAdmin() {
			c.JSON(http.StatusForbidden, gin.H{"detail": "Cannot change superadmin role"})
			return
		}
		if input.Role != "user" && input.Role != "admin" {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Role must be 'user' or 'admin'"})
			return
		}
		// Only superadmin can promote to admin
		if input.Role == "admin" && !me.IsSuperAdmin() {
			c.JSON(http.StatusForbidden, gin.H{"detail": "Only superadmin can assign admin role"})
			return
		}
		updates["role"] = input.Role
	}

	if input.Active != nil {
		// Cannot deactivate superadmin
		if target.IsSuperAdmin() && !*input.Active {
			c.JSON(http.StatusForbidden, gin.H{"detail": "Cannot deactivate superadmin"})
			return
		}
		updates["active"] = *input.Active
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "No fields to update"})
		return
	}

	db.DB.Model(&target).Updates(updates)
	db.DB.First(&target, target.ID)
	c.JSON(http.StatusOK, gin.H{
		"ID": target.ID, "Username": target.Username,
		"Email": target.Email, "Role": target.Role, "Active": target.Active,
	})
}

func DeleteUser(c *gin.Context) {
	caller, _ := c.Get("user")
	me := caller.(models.User)
	id := c.Param("id")

	var target models.User
	if err := db.DB.First(&target, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "User not found"})
		return
	}

	// Cannot delete superadmin
	if target.IsSuperAdmin() {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Cannot delete superadmin"})
		return
	}

	// Cannot delete yourself
	if target.ID == me.ID {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Cannot delete yourself"})
		return
	}

	// Admin cannot delete other admins
	if target.IsAdmin() && !me.IsSuperAdmin() {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only superadmin can delete admin users"})
		return
	}

	db.DB.Delete(&target)
	c.JSON(http.StatusOK, gin.H{"detail": "User deleted"})
}
