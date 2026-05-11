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

// LastScanPortEntry represents a single open port entry in the last scan summary.
type LastScanPortEntry struct {
	IPAddress  string `json:"ip_address"`
	PortNumber int    `json:"port_number"`
	Protocol   string `json:"protocol"`
	Service    string `json:"service"`
	Version    string `json:"version"`
}

// LastScanSummary contains a brief summary of the most recent completed scan for a task.
type LastScanSummary struct {
	RunID       uint                `json:"run_id"`
	ReportID    uint                `json:"report_id"`
	TotalOpen   int                 `json:"total_open"`
	TotalHosts  int                 `json:"total_hosts"`
	TopPorts    []LastScanPortEntry `json:"top_ports"`
}

// ScanTaskWithSummary wraps ScanTask with an optional last scan summary.
type ScanTaskWithSummary struct {
	models.ScanTask
	LastScanSummary *LastScanSummary `json:"last_scan_summary"`
}

func buildLastScanSummary(taskID uint) *LastScanSummary {
	// Find the most recent completed scan run with a report for this task.
	var run models.ScanRun
	if err := db.DB.Preload("Report").
		Where("task_id = ? AND status = 'completed'", taskID).
		Order("id DESC").First(&run).Error; err != nil {
		return nil
	}
	if run.Report == nil {
		return nil
	}

	// Count total open ports across all hosts.
	var totalOpen int64
	db.DB.Model(&models.PortFinding{}).
		Joins("JOIN host_findings ON host_findings.id = port_findings.host_id").
		Where("host_findings.report_id = ? AND port_findings.state = 'open'", run.Report.ID).
		Count(&totalOpen)

	// Count total hosts.
	var totalHosts int64
	db.DB.Model(&models.HostFinding{}).
		Where("report_id = ?", run.Report.ID).
		Count(&totalHosts)

	// Fetch up to 10 open ports with host info.
	type rawPort struct {
		IPAddress  string
		PortNumber int
		Protocol   string
		Service    string
		Version    string
	}
	var rawPorts []rawPort
	db.DB.Model(&models.PortFinding{}).
		Select("host_findings.ip_address, port_findings.port_number, port_findings.protocol, port_findings.service, port_findings.version").
		Joins("JOIN host_findings ON host_findings.id = port_findings.host_id").
		Where("host_findings.report_id = ? AND port_findings.state = 'open'", run.Report.ID).
		Order("host_findings.ip_address ASC, port_findings.port_number ASC").
		Limit(10).
		Scan(&rawPorts)

	topPorts := make([]LastScanPortEntry, len(rawPorts))
	for i, p := range rawPorts {
		topPorts[i] = LastScanPortEntry{
			IPAddress:  p.IPAddress,
			PortNumber: p.PortNumber,
			Protocol:   p.Protocol,
			Service:    p.Service,
			Version:    p.Version,
		}
	}

	return &LastScanSummary{
		RunID:      run.ID,
		ReportID:   run.Report.ID,
		TotalOpen:  int(totalOpen),
		TotalHosts: int(totalHosts),
		TopPorts:   topPorts,
	}
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
	page, perPage := parsePagination(c)

	var total int64
	db.DB.Model(&models.ScanTask{}).Where("user_id = ?", u.ID).Count(&total)

	var tasks []models.ScanTask
	db.DB.Preload("TargetGroups").Preload("ScanRuns").Where("user_id = ?", u.ID).
		Order("id DESC").Offset(offset(page, perPage)).Limit(perPage).Find(&tasks)

	// Enrich each task with its last scan summary.
	enriched := make([]ScanTaskWithSummary, len(tasks))
	for i, t := range tasks {
		enriched[i] = ScanTaskWithSummary{
			ScanTask:        t,
			LastScanSummary: buildLastScanSummary(t.ID),
		}
	}

	c.JSON(http.StatusOK, paginatedResponse(enriched, total, page, perPage))
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

type UpdateScanTaskInput struct {
	Name           *string `json:"name"`
	Description    *string `json:"description"`
	ScanProfile    *string `json:"scan_profile"`
	CustomArgs     *string `json:"custom_args"`
	TargetGroupIDs *[]uint `json:"target_group_ids"`
}

func UpdateScanTask(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var task models.ScanTask
	if err := db.DB.Where("id = ? AND user_id = ?", id, u.ID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan task not found"})
		return
	}

	var input UpdateScanTaskInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if input.Name != nil && *input.Name != "" {
		updates["name"] = *input.Name
	}
	if input.Description != nil {
		updates["description"] = *input.Description
	}
	if input.ScanProfile != nil {
		updates["scan_profile"] = *input.ScanProfile
		// Clear custom args when switching to a profile
		if *input.ScanProfile != "" {
			updates["custom_args"] = ""
		}
	}
	if input.CustomArgs != nil {
		updates["custom_args"] = *input.CustomArgs
	}

	if len(updates) > 0 {
		db.DB.Model(&task).Updates(updates)
	}

	// Update target groups if provided
	if input.TargetGroupIDs != nil {
		db.DB.Model(&task).Association("TargetGroups").Clear()
		for _, gid := range *input.TargetGroupIDs {
			var tg models.TargetGroup
			if db.DB.Where("id = ? AND user_id = ?", gid, u.ID).First(&tg).Error == nil {
				db.DB.Model(&task).Association("TargetGroups").Append(&tg)
			}
		}
	}

	db.DB.Preload("TargetGroups").Preload("ScanRuns.Report").First(&task, task.ID)
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

		// Block if a scan is already queued or running for this task
		var activeCount int64
		db.DB.Model(&models.ScanRun{}).Where("task_id = ? AND status IN ?", task.ID, []string{"queued", "running"}).Count(&activeCount)
		if activeCount > 0 {
			c.JSON(http.StatusConflict, gin.H{"detail": "A scan for this task is already queued or running"})
			return
		}

		run := models.ScanRun{TaskID: task.ID, Status: "queued"}
		db.DB.Create(&run)

		// Push to Redis queue for worker
		services.GetRedis().LPush(c.Request.Context(), services.ScanQueueKey(), run.ID)

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

func ListScanRuns(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)
	page, perPage := parsePagination(c)

	status := c.Query("status")

	query := db.DB.Model(&models.ScanRun{}).
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ?", u.ID)
	if status != "" {
		query = query.Where("scan_runs.status = ?", status)
	}

	var total int64
	query.Count(&total)

	var runs []models.ScanRun
	q := db.DB.Preload("Task").Preload("Report").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ?", u.ID)
	if status != "" {
		q = q.Where("scan_runs.status = ?", status)
	}
	q.Order("scan_runs.id DESC").Offset(offset(page, perPage)).Limit(perPage).Find(&runs)

	c.JSON(http.StatusOK, paginatedResponse(runs, total, page, perPage))
}
