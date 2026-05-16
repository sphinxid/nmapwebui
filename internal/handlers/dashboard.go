package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

// DashboardRun is a lightweight run object used by the dashboard.
type DashboardRun struct {
	ID          uint       `json:"ID"`
	TaskID      uint       `json:"TaskID"`
	TaskName    string     `json:"TaskName"`
	Status      string     `json:"Status"`
	Progress    int        `json:"Progress"`
	StartedAt   *time.Time `json:"StartedAt"`
	CompletedAt *time.Time `json:"CompletedAt"`
}

// DashboardActivityDay holds the completed scan count for a single day.
type DashboardActivityDay struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// DashboardStats is the response shape for GET /api/dashboard/stats.
type DashboardStats struct {
	TotalTasks    int64                  `json:"total_tasks"`
	RunningScans  int64                  `json:"running_scans"`
	TotalReports  int64                  `json:"total_reports"`
	ActiveRuns    []DashboardRun         `json:"active_runs"`
	RecentRuns    []DashboardRun         `json:"recent_runs"`
	StatusCounts  map[string]int64       `json:"status_counts"`
	ActivityLast7 []DashboardActivityDay `json:"activity_last7"`
}

// GetDashboardStats returns aggregated data for the dashboard in a single request.
func GetDashboardStats(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)

	var stats DashboardStats

	// --- Scalar counts (3 cheap COUNT queries) ---
	db.DB.Model(&models.ScanTask{}).Where("user_id = ?", u.ID).Count(&stats.TotalTasks)

	db.DB.Model(&models.ScanRun{}).
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ? AND scan_runs.status = ?", u.ID, "running").
		Count(&stats.RunningScans)

	db.DB.Model(&models.ScanReport{}).
		Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ?", u.ID).
		Count(&stats.TotalReports)

	// --- Active runs (running or queued) ---
	var activeRunRows []struct {
		ID          uint
		TaskID      uint
		TaskName    string
		Status      string
		Progress    int
		StartedAt   *time.Time
		CompletedAt *time.Time
	}
	db.DB.Model(&models.ScanRun{}).
		Select("scan_runs.id, scan_runs.task_id, scan_tasks.name as task_name, scan_runs.status, scan_runs.progress, scan_runs.started_at, scan_runs.completed_at").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ? AND scan_runs.status IN ?", u.ID, []string{"running", "queued"}).
		Order("scan_runs.id DESC").
		Scan(&activeRunRows)

	stats.ActiveRuns = make([]DashboardRun, 0, len(activeRunRows))
	for _, r := range activeRunRows {
		stats.ActiveRuns = append(stats.ActiveRuns, DashboardRun{
			ID: r.ID, TaskID: r.TaskID, TaskName: r.TaskName,
			Status: r.Status, Progress: r.Progress,
			StartedAt: r.StartedAt, CompletedAt: r.CompletedAt,
		})
	}

	// --- Recent runs (last 10 completed/failed + any active, ordered by id desc) ---
	var recentRunRows []struct {
		ID          uint
		TaskID      uint
		TaskName    string
		Status      string
		Progress    int
		StartedAt   *time.Time
		CompletedAt *time.Time
	}
	db.DB.Model(&models.ScanRun{}).
		Select("scan_runs.id, scan_runs.task_id, scan_tasks.name as task_name, scan_runs.status, scan_runs.progress, scan_runs.started_at, scan_runs.completed_at").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ?", u.ID).
		Order("scan_runs.id DESC").
		Limit(10).
		Scan(&recentRunRows)

	stats.RecentRuns = make([]DashboardRun, 0, len(recentRunRows))
	for _, r := range recentRunRows {
		stats.RecentRuns = append(stats.RecentRuns, DashboardRun{
			ID: r.ID, TaskID: r.TaskID, TaskName: r.TaskName,
			Status: r.Status, Progress: r.Progress,
			StartedAt: r.StartedAt, CompletedAt: r.CompletedAt,
		})
	}

	// --- Status counts (all-time, for doughnut chart) ---
	type statusCount struct {
		Status string
		Count  int64
	}
	var statusRows []statusCount
	db.DB.Model(&models.ScanRun{}).
		Select("scan_runs.status, COUNT(*) as count").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ?", u.ID).
		Group("scan_runs.status").
		Scan(&statusRows)

	stats.StatusCounts = map[string]int64{
		"queued": 0, "running": 0, "completed": 0, "failed": 0,
	}
	for _, row := range statusRows {
		stats.StatusCounts[row.Status] = row.Count
	}

	// --- Activity last 7 days (completed scans per day) ---
	now := time.Now()
	stats.ActivityLast7 = make([]DashboardActivityDay, 7)
	for i := 0; i < 7; i++ {
		dayStart := time.Date(now.Year(), now.Month(), now.Day()-6+i, 0, 0, 0, 0, now.Location())
		dayEnd := dayStart.Add(24 * time.Hour)
		label := dayStart.Format("Mon, Jan 2")

		var count int64
		db.DB.Model(&models.ScanRun{}).
			Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
			Where("scan_tasks.user_id = ? AND scan_runs.status = ? AND scan_runs.completed_at >= ? AND scan_runs.completed_at < ?",
				u.ID, "completed", dayStart, dayEnd).
			Count(&count)

		stats.ActivityLast7[i] = DashboardActivityDay{Date: label, Count: int(count)}
	}

	c.JSON(http.StatusOK, stats)
}
