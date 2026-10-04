package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

type SearchHit struct {
	Type     string `json:"type"`
	ID       uint   `json:"id,omitempty"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	URL      string `json:"url"`
}

// Search powers the command palette: tasks, target groups, hosts and reports
// matching a free-text query, a handful of each.
func Search(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)
	q := strings.TrimSpace(c.Query("q"))
	if len(q) < 1 {
		c.JSON(http.StatusOK, gin.H{"tasks": []SearchHit{}, "groups": []SearchHit{}, "hosts": []SearchHit{}, "reports": []SearchHit{}})
		return
	}
	like := "%" + q + "%"
	const limit = 6

	tasks := []SearchHit{}
	var taskRows []models.ScanTask
	db.DB.Where("user_id = ? AND name LIKE ?", u.ID, like).Order("name").Limit(limit).Find(&taskRows)
	for _, t := range taskRows {
		sub := t.ScanProfile
		if sub == "" {
			sub = "custom arguments"
		}
		tasks = append(tasks, SearchHit{Type: "task", ID: t.ID, Title: t.Name, Subtitle: sub, URL: "/tasks/view/" + strconv.Itoa(int(t.ID))})
	}

	groups := []SearchHit{}
	var groupRows []models.TargetGroup
	db.DB.Where("user_id = ? AND (name LIKE ? OR id IN (SELECT target_group_id FROM targets WHERE value LIKE ? AND deleted_at IS NULL))", u.ID, like, like).
		Order("name").Limit(limit).Find(&groupRows)
	for _, g := range groupRows {
		groups = append(groups, SearchHit{Type: "group", ID: g.ID, Title: g.Name, Subtitle: g.Description, URL: "/targets"})
	}

	hosts := []SearchHit{}
	var hostRows []struct {
		IPAddress string
		Hostname  string
	}
	db.DB.Table("host_findings").
		Select("host_findings.ip_address, MAX(host_findings.hostname) AS hostname").
		Joins("JOIN scan_reports ON scan_reports.id = host_findings.report_id").
		Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ? AND host_findings.deleted_at IS NULL AND (host_findings.ip_address LIKE ? OR host_findings.hostname LIKE ?)", u.ID, like, like).
		Group("host_findings.ip_address").Order("host_findings.ip_address").Limit(limit).Scan(&hostRows)
	for _, h := range hostRows {
		hosts = append(hosts, SearchHit{Type: "host", Title: h.IPAddress, Subtitle: h.Hostname, URL: "/hosts?ip=" + h.IPAddress})
	}

	reports := []SearchHit{}
	if id, err := strconv.Atoi(strings.TrimPrefix(q, "#")); err == nil && id > 0 {
		var rep struct {
			ID       uint
			TaskName string
		}
		db.DB.Table("scan_reports").Select("scan_reports.id, scan_tasks.name AS task_name").
			Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
			Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
			Where("scan_reports.id = ? AND scan_tasks.user_id = ? AND scan_reports.deleted_at IS NULL", id, u.ID).Scan(&rep)
		if rep.ID != 0 {
			reports = append(reports, SearchHit{Type: "report", ID: rep.ID, Title: "Report #" + strconv.Itoa(int(rep.ID)), Subtitle: rep.TaskName, URL: "/reports/" + strconv.Itoa(int(rep.ID))})
		}
		var run models.ScanRun
		if db.DB.Preload("Task").First(&run, id).Error == nil && run.Task.UserID == u.ID {
			reports = append(reports, SearchHit{Type: "run", ID: run.ID, Title: "Run #" + strconv.Itoa(int(run.ID)), Subtitle: run.Task.Name + " · " + run.Status, URL: "/tasks/run/" + strconv.Itoa(int(run.ID))})
		}
	}

	c.JSON(http.StatusOK, gin.H{"tasks": tasks, "groups": groups, "hosts": hosts, "reports": reports})
}
