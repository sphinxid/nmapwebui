package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/config"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
	"nmapwebui/internal/services"
)

type ScanTaskInput struct {
	Name                string   `json:"name" binding:"required"`
	Description         string   `json:"description"`
	ScanProfile         string   `json:"scan_profile"`
	CustomArgs          string   `json:"custom_args"`
	IsScheduled         bool     `json:"is_scheduled"`
	ScheduleType        string   `json:"schedule_type"`
	ScheduleData        string   `json:"schedule_data"`
	UseGlobalMaxReports bool     `json:"use_global_max_reports"`
	MaxReports          *int      `json:"max_reports"`
	TargetGroupIDs      []uint    `json:"target_group_ids"`
}

func ListScanProfiles(c *gin.Context) {
	var profiles []gin.H
	for k, v := range config.DefaultProfiles {
		profiles = append(profiles, gin.H{"name": k, "nmap_args": v})
	}
	c.JSON(http.StatusOK, profiles)
}

func ListScanTasks(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)
	var tasks []models.ScanTask
	db.DB.Preload("TargetGroups").Where("user_id = ?", u.ID).Find(&tasks)
	c.JSON(http.StatusOK, tasks)
}

func CreateScanTask(c *gin.Context) {
	var input ScanTaskInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}
	user, _ := c.Get("user")
	u := user.(models.User)

	task := models.ScanTask{
		Name:                input.Name,
		Description:         input.Description,
		ScanProfile:         input.ScanProfile,
		CustomArgs:          input.CustomArgs,
		UserID:              u.ID,
		IsScheduled:         input.IsScheduled,
		ScheduleType:        input.ScheduleType,
		ScheduleData:        input.ScheduleData,
		UseGlobalMaxReports: input.UseGlobalMaxReports,
		MaxReports:          input.MaxReports,
	}
	if err := db.DB.Create(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	for _, gid := range input.TargetGroupIDs {
		var tg models.TargetGroup
		if db.DB.Where("id = ? AND user_id = ?", gid, u.ID).First(&tg).Error == nil {
			db.DB.Model(&task).Association("TargetGroups").Append(&tg)
		}
	}

	db.DB.Preload("TargetGroups").First(&task, task.ID)
	c.JSON(http.StatusCreated, task)
}

func GetScanTask(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var task models.ScanTask
	if err := db.DB.Preload("TargetGroups").Preload("ScanRuns.Report").Where("id = ? AND user_id = ?", id, u.ID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan task not found"})
		return
	}
	c.JSON(http.StatusOK, task)
}

func DeleteScanTask(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var task models.ScanTask
	if err := db.DB.Where("id = ? AND user_id = ?", id, u.ID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan task not found"})
		return
	}
	db.DB.Delete(&task)
	c.Status(http.StatusNoContent)
}

func RunScanTask(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		user, _ := c.Get("user")
		u := user.(models.User)

		var task models.ScanTask
		if err := db.DB.Where("id = ? AND user_id = ?", id, u.ID).First(&task).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"detail": "Scan task not found"})
			return
		}

		// Check if already running
		var count int64
		db.DB.Model(&models.ScanRun{}).Where("task_id = ? AND status IN ?", task.ID, []string{"queued", "running"}).Count(&count)
		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"detail": "A scan for this task is already queued or running"})
			return
		}

		run := models.ScanRun{TaskID: task.ID, Status: "queued"}
		db.DB.Create(&run)

		// Push to Redis queue for worker
		job, _ := services.GetRedis().LPush(c.Request.Context(), services.ScanQueueKey(), run.ID).Result()
		_ = job

		c.JSON(http.StatusOK, run)
	}
}

func GetScanRun(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var run models.ScanRun
	if err := db.DB.Preload("Task").Preload("Report").First(&run, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan run not found"})
		return
	}
	if run.Task.UserID != u.ID {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan run not found"})
		return
	}
	c.JSON(http.StatusOK, run)
}
