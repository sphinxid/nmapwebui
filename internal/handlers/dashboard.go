package handlers

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
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
	Activity      []DashboardActivityDay `json:"activity"`
	Period        string                 `json:"period"`
	TopServices   []ServiceCount         `json:"top_services"`
	ExposedHosts  []ExposedHost          `json:"exposed_hosts"`
	RecentChanges []RecentChange         `json:"recent_changes"`
	Inventory     InventorySummary       `json:"inventory"`
}

type ServiceCount struct {
	Service string `json:"service"`
	Hosts   int    `json:"hosts"`
}

type ExposedHost struct {
	IPAddress string `json:"ip_address"`
	Hostname  string `json:"hostname"`
	OpenPorts int    `json:"open_ports"`
	High      int    `json:"high"`
}

type RecentChange struct {
	ReportID  uint        `json:"report_id"`
	TaskID    uint        `json:"task_id"`
	TaskName  string      `json:"task_name"`
	CreatedAt time.Time   `json:"created_at"`
	Summary   interface{} `json:"summary"`
	Total     int         `json:"total"`
}

type InventorySummary struct {
	Hosts     int `json:"hosts"`
	HostsUp   int `json:"hosts_up"`
	OpenPorts int `json:"open_ports"`
	Notable   int `json:"notable"`
	High      int `json:"high"`
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
		"queued": 0, "running": 0, "completed": 0, "failed": 0, "cancelled": 0,
	}
	for _, row := range statusRows {
		stats.StatusCounts[row.Status] = row.Count
	}

	// --- Activity chart: period-aware (day=last 24h by hour, week=last 7 days, month=last 30 days) ---
	period := c.DefaultQuery("period", "week")
	if period != "day" && period != "week" && period != "month" {
		period = "week"
	}
	stats.Period = period

	now := time.Now()
	switch period {
	case "day":
		// Last 24 hours, one bucket per hour
		stats.Activity = make([]DashboardActivityDay, 24)
		for i := 0; i < 24; i++ {
			bucketStart := time.Date(now.Year(), now.Month(), now.Day(), now.Hour()-23+i, 0, 0, 0, now.Location())
			bucketEnd := bucketStart.Add(time.Hour)
			label := bucketStart.Format("15:04")
			var count int64
			db.DB.Model(&models.ScanRun{}).
				Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
				Where("scan_tasks.user_id = ? AND scan_runs.status = ? AND scan_runs.completed_at >= ? AND scan_runs.completed_at < ?",
					u.ID, "completed", bucketStart, bucketEnd).
				Count(&count)
			stats.Activity[i] = DashboardActivityDay{Date: label, Count: int(count)}
		}
	case "month":
		// Last 30 days, one bucket per day
		stats.Activity = make([]DashboardActivityDay, 30)
		for i := 0; i < 30; i++ {
			dayStart := time.Date(now.Year(), now.Month(), now.Day()-29+i, 0, 0, 0, 0, now.Location())
			dayEnd := dayStart.Add(24 * time.Hour)
			label := dayStart.Format("Jan 2")
			var count int64
			db.DB.Model(&models.ScanRun{}).
				Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
				Where("scan_tasks.user_id = ? AND scan_runs.status = ? AND scan_runs.completed_at >= ? AND scan_runs.completed_at < ?",
					u.ID, "completed", dayStart, dayEnd).
				Count(&count)
			stats.Activity[i] = DashboardActivityDay{Date: label, Count: int(count)}
		}
	default: // week
		// Last 7 days, one bucket per day
		stats.Activity = make([]DashboardActivityDay, 7)
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
			stats.Activity[i] = DashboardActivityDay{Date: label, Count: int(count)}
		}
	}

	// --- Current estate (latest report per task) ---
	rows := loadHostRows(u.ID, func(q *gorm.DB) *gorm.DB {
		return q.Where("host_findings.report_id IN (?)", latestReportIDs(u.ID))
	})
	hosts := aggregateHosts(rows)
	svcHosts := map[string]int{}
	stats.ExposedHosts = []ExposedHost{}
	for _, h := range hosts {
		stats.Inventory.Hosts++
		if h.Status == "up" {
			stats.Inventory.HostsUp++
		}
		stats.Inventory.OpenPorts += h.OpenPorts
		if len(h.Notable) > 0 {
			stats.Inventory.Notable++
		}
		if h.MaxSeverity == "high" {
			stats.Inventory.High++
		}
		for _, svc := range h.Services {
			svcHosts[svc]++
		}
		high := 0
		for _, n := range h.Notable {
			if n.Notable != nil && n.Notable.Severity == "high" {
				high++
			}
		}
		if h.OpenPorts > 0 {
			stats.ExposedHosts = append(stats.ExposedHosts, ExposedHost{IPAddress: h.IPAddress, Hostname: h.Hostname, OpenPorts: h.OpenPorts, High: high})
		}
	}
	sort.Slice(stats.ExposedHosts, func(i, j int) bool {
		if stats.ExposedHosts[i].High != stats.ExposedHosts[j].High {
			return stats.ExposedHosts[i].High > stats.ExposedHosts[j].High
		}
		return stats.ExposedHosts[i].OpenPorts > stats.ExposedHosts[j].OpenPorts
	})
	if len(stats.ExposedHosts) > 6 {
		stats.ExposedHosts = stats.ExposedHosts[:6]
	}
	stats.TopServices = []ServiceCount{}
	for svc, n := range svcHosts {
		stats.TopServices = append(stats.TopServices, ServiceCount{Service: svc, Hosts: n})
	}
	sort.Slice(stats.TopServices, func(i, j int) bool {
		if stats.TopServices[i].Hosts != stats.TopServices[j].Hosts {
			return stats.TopServices[i].Hosts > stats.TopServices[j].Hosts
		}
		return stats.TopServices[i].Service < stats.TopServices[j].Service
	})
	if len(stats.TopServices) > 8 {
		stats.TopServices = stats.TopServices[:8]
	}

	// --- Recent changes: diff the newest reports against their predecessors ---
	stats.RecentChanges = []RecentChange{}
	var recentReports []models.ScanReport
	db.DB.Preload("Hosts.Ports").Preload("ScanRun.Task").
		Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ? AND scan_tasks.deleted_at IS NULL", u.ID).
		Order("scan_reports.id DESC").Limit(6).Find(&recentReports)
	for _, r := range recentReports {
		d := computeDiff(r, previousReport(r))
		if !d.HasPrevious {
			continue
		}
		total := d.Summary.NewHosts + d.Summary.RemovedHosts + d.Summary.StatusChanges + d.Summary.OpenedPorts + d.Summary.ClosedPorts + d.Summary.ChangedService
		name := ""
		if r.ScanRun != nil {
			name = r.ScanRun.Task.Name
		}
		stats.RecentChanges = append(stats.RecentChanges, RecentChange{ReportID: r.ID, TaskID: r.ScanRun.TaskID, TaskName: name, CreatedAt: r.CreatedAt, Summary: d.Summary, Total: total})
	}

	c.JSON(http.StatusOK, stats)
}
