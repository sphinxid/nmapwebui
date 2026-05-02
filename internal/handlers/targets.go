package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

type TargetInput struct {
	Value      string `json:"value" binding:"required"`
	TargetType string `json:"target_type"`
}

type TargetGroupInput struct {
	Name        string         `json:"name" binding:"required"`
	Description string         `json:"description"`
	Targets     []TargetInput  `json:"targets"`
}

func ListTargetGroups(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)
	page, perPage := parsePagination(c)

	var total int64
	db.DB.Model(&models.TargetGroup{}).Where("user_id = ?", u.ID).Count(&total)

	var groups []models.TargetGroup
	db.DB.Preload("Targets").Where("user_id = ?", u.ID).
		Order("id DESC").Offset(offset(page, perPage)).Limit(perPage).Find(&groups)

	c.JSON(http.StatusOK, paginatedResponse(groups, total, page, perPage))
}

func CreateTargetGroup(c *gin.Context) {
	var input TargetGroupInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}
	user, _ := c.Get("user")
	u := user.(models.User)

	group := models.TargetGroup{
		Name:        input.Name,
		Description: input.Description,
		UserID:      u.ID,
	}
	if err := db.DB.Create(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	for _, t := range input.Targets {
		typeStr := t.TargetType
		if typeStr == "" {
			typeStr = "ip"
		}
		target := models.Target{
			Value:         t.Value,
			TargetType:    typeStr,
			TargetGroupID: group.ID,
		}
		db.DB.Create(&target)
	}

	db.DB.Preload("Targets").First(&group, group.ID)
	c.JSON(http.StatusCreated, group)
}

func GetTargetGroup(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var group models.TargetGroup
	if err := db.DB.Preload("Targets").Where("id = ? AND user_id = ?", id, u.ID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Target group not found"})
		return
	}
	c.JSON(http.StatusOK, group)
}

func DeleteTargetGroup(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var group models.TargetGroup
	if err := db.DB.Where("id = ? AND user_id = ?", id, u.ID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Target group not found"})
		return
	}
	db.DB.Delete(&group)
	c.Status(http.StatusNoContent)
}
