package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nmapwebui/internal/config"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
	"nmapwebui/internal/scheduler"
	"nmapwebui/internal/services"
)

type ScanTaskInput struct {
	Name                string `json:"name" binding:"required"`
	Description         string `json:"description"`
	ScanProfile         string `json:"scan_profile"`
	CustomArgs          string `json:"custom_args"`
	IsScheduled         bool   `json:"is_scheduled"`
	ScheduleType        string `json:"schedule_type"`
	ScheduleData        string `json:"schedule_data"`
	UseGlobalMaxReports bool   `json:"use_global_max_reports"`
	MaxReports          *int   `json:"max_reports"`
	TargetGroupIDs      []uint `json:"target_group_ids"`
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
	RunID      uint                `json:"run_id"`
	ReportID   uint                `json:"report_id"`
	TotalOpen  int                 `json:"total_open"`
	TotalHosts int                 `json:"total_hosts"`
	TopPorts   []LastScanPortEntry `json:"top_ports"`
}

// TaskRunBrief is the minimal description of a run shown on list cards.
type TaskRunBrief struct {
	ID           uint       `json:"id"`
	Status       string     `json:"status"`
	Progress     int        `json:"progress"`
	StartedAt    *time.Time `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	CreatedAt    time.Time  `json:"created_at"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

// ScanTaskWithSummary wraps ScanTask with list-oriented enrichment: the last
// completed scan's findings, the most recent run of any status, the currently
// active run (if any) and the next scheduled fire time.
type ScanTaskWithSummary struct {
	models.ScanTask
	LastScanSummary *LastScanSummary `json:"last_scan_summary"`
	LastRun         *TaskRunBrief    `json:"last_run"`
	ActiveRun       *TaskRunBrief    `json:"active_run"`
	NextRun         *time.Time       `json:"next_run"`
	TargetCount     int              `json:"target_count"`
}

func briefOf(r models.ScanRun) *TaskRunBrief {
	return &TaskRunBrief{
		ID: r.ID, Status: r.Status, Progress: r.Progress,
		StartedAt: r.StartedAt, CompletedAt: r.CompletedAt, CreatedAt: r.CreatedAt,
		ErrorMessage: r.ErrorMessage,
	}
}

func enrichTask(t models.ScanTask, tz *time.Location) ScanTaskWithSummary {
	out := ScanTaskWithSummary{ScanTask: t, LastScanSummary: buildLastScanSummary(t.ID)}

	var last models.ScanRun
	if err := db.DB.Where("task_id = ?", t.ID).Order("id DESC").First(&last).Error; err == nil {
		out.LastRun = briefOf(last)
		if last.Status == "queued" || last.Status == "running" {
			out.ActiveRun = out.LastRun
		}
	}
	out.NextRun = scheduler.NextRun(t, tz)
	for _, g := range t.TargetGroups {
		out.TargetCount += len(g.Targets)
	}
	return out
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

	base := db.DB.Model(&models.ScanTask{}).Where("user_id = ?", u.ID)
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		base = base.Where("name LIKE ?", "%"+q+"%")
	}
	switch c.Query("scheduled") {
	case "1", "true":
		base = base.Where("is_scheduled = ?", true)
	case "0", "false":
		base = base.Where("is_scheduled = ?", false)
	}

	base = base.Session(&gorm.Session{})

	var total int64
	base.Count(&total)

	var tasks []models.ScanTask
	base.Preload("TargetGroups.Targets").
		Order("id DESC").Offset(offset(page, perPage)).Limit(perPage).Find(&tasks)

	tz := scheduler.UserLocation(u.ID)
	enriched := make([]ScanTaskWithSummary, len(tasks))
	for i, t := range tasks {
		enriched[i] = enrichTask(t, tz)
	}

	c.JSON(http.StatusOK, paginatedResponse(enriched, total, page, perPage))
}

// ListScanTaskOptions returns id/name pairs for filter dropdowns.
func ListScanTaskOptions(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)
	var rows []struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	}
	db.DB.Model(&models.ScanTask{}).Select("id, name").Where("user_id = ?", u.ID).Order("name ASC").Scan(&rows)
	if rows == nil {
		rows = []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		}{}
	}
	c.JSON(http.StatusOK, rows)
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
	if err := db.DB.Preload("TargetGroups.Targets").Preload("ScanRuns.Report").Where("id = ? AND user_id = ?", id, u.ID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan task not found"})
		return
	}
	c.JSON(http.StatusOK, enrichTask(task, scheduler.UserLocation(u.ID)))
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

// CancelScanRun stops a queued or running scan. Queued runs are finalised
// immediately; running ones are flagged in Redis and the worker kills nmap
// within about a second, then publishes the terminal "cancelled" event.
func CancelScanRun(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var run models.ScanRun
	if err := db.DB.Preload("Task").First(&run, id).Error; err != nil || run.Task.UserID != u.ID {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan run not found"})
		return
	}

	switch run.Status {
	case "queued":
		// Flag first so a worker that pops the job concurrently sees it.
		services.RequestCancel(c.Request.Context(), run.ID)
		db.DB.Model(&run).Updates(map[string]interface{}{
			"status": "cancelled", "completed_at": time.Now(), "error_message": "Cancelled by user before start",
		})
		c.JSON(http.StatusOK, gin.H{"detail": "Scan cancelled", "status": "cancelled"})
	case "running":
		if err := services.RequestCancel(c.Request.Context(), run.ID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Could not reach the job queue"})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"detail": "Cancellation requested", "status": "running"})
	default:
		c.JSON(http.StatusConflict, gin.H{"detail": "Scan is already " + run.Status})
	}
}

func ListScanRuns(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)
	page, perPage := parsePagination(c)

	applyFilters := func(q *gorm.DB) *gorm.DB {
		q = q.Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
			Where("scan_tasks.user_id = ? AND scan_tasks.deleted_at IS NULL", u.ID)
		if status := c.Query("status"); status != "" {
			q = q.Where("scan_runs.status = ?", status)
		}
		if taskID := c.Query("task_id"); taskID != "" {
			q = q.Where("scan_runs.task_id = ?", taskID)
		}
		return q
	}

	var total int64
	applyFilters(db.DB.Model(&models.ScanRun{})).Count(&total)

	var runs []models.ScanRun
	applyFilters(db.DB.Preload("Task").Preload("Report")).
		Order("scan_runs.id DESC").Offset(offset(page, perPage)).Limit(perPage).Find(&runs)

	c.JSON(http.StatusOK, paginatedResponse(runs, total, page, perPage))
}
