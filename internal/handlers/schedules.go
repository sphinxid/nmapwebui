package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

type ScheduleInput struct {
	ScheduleType string `json:"schedule_type" binding:"required"`
	ScheduleData string `json:"schedule_data"`
}

func ScheduleTask(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var input ScheduleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	var task models.ScanTask
	if err := db.DB.Where("id = ? AND user_id = ?", id, u.ID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan task not found"})
		return
	}

	task.IsScheduled = true
	task.ScheduleType = input.ScheduleType
	task.ScheduleData = input.ScheduleData
	db.DB.Save(&task)
	c.JSON(http.StatusOK, gin.H{"detail": "Task scheduled", "task_id": task.ID})
}

func UnscheduleTask(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var task models.ScanTask
	if err := db.DB.Where("id = ? AND user_id = ?", id, u.ID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan task not found"})
		return
	}

	task.IsScheduled = false
	task.ScheduleType = ""
	task.ScheduleData = ""
	db.DB.Save(&task)
	c.JSON(http.StatusOK, gin.H{"detail": "Task unscheduled", "task_id": task.ID})
}
