package handlers

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
	"nmapwebui/internal/services"
)

// latestReportIDs returns a subquery selecting the newest report per task for
// a user. "Current state" of the estate is defined by these reports.
func latestReportIDs(userID uint) *gorm.DB {
	return db.DB.Table("scan_reports").
		Select("MAX(scan_reports.id)").
		Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ? AND scan_reports.deleted_at IS NULL AND scan_tasks.deleted_at IS NULL", userID).
		Group("scan_runs.task_id")
}

type HostPort struct {
	Port     int               `json:"port"`
	Protocol string            `json:"protocol"`
	State    string            `json:"state"`
	Service  string            `json:"service"`
	Version  string            `json:"version"`
	Notable  *services.Notable `json:"notable,omitempty"`
}

type HostTaskRef struct {
	TaskID    uint      `json:"task_id"`
	TaskName  string    `json:"task_name"`
	ReportID  uint      `json:"report_id"`
	ScannedAt time.Time `json:"scanned_at"`
}

// InventoryHost is one row of the host inventory: the union of what the
// latest report of every task says about an IP.
type InventoryHost struct {
	IPAddress   string        `json:"ip_address"`
	Hostname    string        `json:"hostname"`
	Status      string        `json:"status"`
	OSInfo      string        `json:"os_info"`
	OpenPorts   int           `json:"open_ports"`
	Services    []string      `json:"services"`
	Notable     []HostPort    `json:"notable"`
	MaxSeverity string        `json:"max_severity"`
	Tasks       []HostTaskRef `json:"tasks"`
	FirstSeen   *time.Time    `json:"first_seen"`
	LastSeen    *time.Time    `json:"last_seen"`
	ports       map[string]HostPort
}

type hostRow struct {
	models.HostFinding
	TaskID    uint
	TaskName  string
	ScannedAt time.Time
}

func loadHostRows(userID uint, where func(*gorm.DB) *gorm.DB) []hostRow {
	q := db.DB.Model(&models.HostFinding{}).
		Select("host_findings.*, scan_tasks.id AS task_id, scan_tasks.name AS task_name, scan_reports.created_at AS scanned_at").
		Joins("JOIN scan_reports ON scan_reports.id = host_findings.report_id").
		Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ? AND scan_tasks.deleted_at IS NULL AND scan_reports.deleted_at IS NULL", userID)
	if where != nil {
		q = where(q)
	}
	var rows []hostRow
	q.Order("scan_reports.id DESC").Scan(&rows)
	if len(rows) == 0 {
		return rows
	}
	ids := make([]uint, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	var ports []models.PortFinding
	db.DB.Where("host_id IN ?", ids).Find(&ports)
	byHost := map[uint][]models.PortFinding{}
	for _, p := range ports {
		byHost[p.HostID] = append(byHost[p.HostID], p)
	}
	for i := range rows {
		rows[i].Ports = byHost[rows[i].ID]
	}
	return rows
}

func toHostPort(p models.PortFinding) HostPort {
	hp := HostPort{Port: p.PortNumber, Protocol: p.Protocol, State: p.State, Service: p.Service, Version: p.Version}
	if p.State == "open" {
		if n, ok := services.NotableFor(p.PortNumber, p.Protocol, p.Service); ok {
			hp.Notable = &n
		}
	}
	return hp
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}

// aggregateHosts merges host rows (possibly from several tasks) by IP.
func aggregateHosts(rows []hostRow) []*InventoryHost {
	byIP := map[string]*InventoryHost{}
	var order []string
	for _, r := range rows {
		h, ok := byIP[r.IPAddress]
		if !ok {
			h = &InventoryHost{IPAddress: r.IPAddress, Status: r.Status, ports: map[string]HostPort{}}
			byIP[r.IPAddress] = h
			order = append(order, r.IPAddress)
		}
		if h.Hostname == "" {
			h.Hostname = r.Hostname
		}
		if h.OSInfo == "" {
			h.OSInfo = r.OSInfo
		}
		if r.Status == "up" {
			h.Status = "up"
		}
		scanned := r.ScannedAt
		if h.LastSeen == nil || scanned.After(*h.LastSeen) {
			h.LastSeen = &scanned
		}
		dup := false
		for _, t := range h.Tasks {
			if t.TaskID == r.TaskID {
				dup = true
				break
			}
		}
		if !dup {
			h.Tasks = append(h.Tasks, HostTaskRef{TaskID: r.TaskID, TaskName: r.TaskName, ReportID: r.ReportID, ScannedAt: scanned})
		}
		for _, p := range r.Ports {
			key := itoa(p.PortNumber) + "/" + p.Protocol
			existing, seen := h.ports[key]
			if !seen || (existing.State != "open" && p.State == "open") {
				h.ports[key] = toHostPort(p)
			}
		}
	}
	out := make([]*InventoryHost, 0, len(order))
	for _, ip := range order {
		h := byIP[ip]
		svc := map[string]bool{}
		for _, p := range h.ports {
			if p.State != "open" {
				continue
			}
			h.OpenPorts++
			if p.Service != "" {
				svc[p.Service] = true
			}
			if p.Notable != nil {
				h.Notable = append(h.Notable, p)
				if severityRank(p.Notable.Severity) > severityRank(h.MaxSeverity) {
					h.MaxSeverity = p.Notable.Severity
				}
			}
		}
		for s := range svc {
			h.Services = append(h.Services, s)
		}
		sort.Strings(h.Services)
		sort.Slice(h.Notable, func(i, j int) bool { return h.Notable[i].Port < h.Notable[j].Port })
		if h.Notable == nil {
			h.Notable = []HostPort{}
		}
		if h.Services == nil {
			h.Services = []string{}
		}
		out = append(out, h)
	}
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }

// firstSeenMap returns, per IP, the creation time of the earliest report that
// contained it. It goes through MIN(report id) rather than MIN(created_at)
// because SQLite hands aggregate timestamps back as text.
func firstSeenMap(userID uint) map[string]time.Time {
	var rows []struct {
		IPAddress     string
		FirstReportID uint
	}
	db.DB.Table("host_findings").
		Select("host_findings.ip_address, MIN(host_findings.report_id) AS first_report_id").
		Joins("JOIN scan_reports ON scan_reports.id = host_findings.report_id").
		Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ? AND host_findings.deleted_at IS NULL", userID).
		Group("host_findings.ip_address").Scan(&rows)
	out := make(map[string]time.Time, len(rows))
	if len(rows) == 0 {
		return out
	}
	ids := make([]uint, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.FirstReportID)
	}
	var reports []models.ScanReport
	db.DB.Select("id, created_at").Where("id IN ?", ids).Find(&reports)
	created := make(map[uint]time.Time, len(reports))
	for _, r := range reports {
		created[r.ID] = r.CreatedAt
	}
	for _, r := range rows {
		if t, ok := created[r.FirstReportID]; ok {
			out[r.IPAddress] = t
		}
	}
	return out
}

// ListHosts returns the host inventory derived from the latest report of
// every task, with filtering, sorting and pagination done in memory (the set
// is bounded by the number of distinct hosts, not by scan history).
func ListHosts(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)
	page, perPage := parsePagination(c)

	taskID := c.Query("task_id")
	rows := loadHostRows(u.ID, func(q *gorm.DB) *gorm.DB {
		q = q.Where("host_findings.report_id IN (?)", latestReportIDs(u.ID))
		if taskID != "" {
			q = q.Where("scan_runs.task_id = ?", taskID)
		}
		return q
	})
	hosts := aggregateHosts(rows)
	first := firstSeenMap(u.ID)
	for _, h := range hosts {
		if t, ok := first[h.IPAddress]; ok {
			tt := t
			h.FirstSeen = &tt
		}
	}

	// Summary over the whole inventory before filters are applied.
	summary := gin.H{"total": len(hosts), "up": 0, "notable": 0, "high": 0, "open_ports": 0}
	for _, h := range hosts {
		if h.Status == "up" {
			summary["up"] = summary["up"].(int) + 1
		}
		if len(h.Notable) > 0 {
			summary["notable"] = summary["notable"].(int) + 1
		}
		if h.MaxSeverity == "high" {
			summary["high"] = summary["high"].(int) + 1
		}
		summary["open_ports"] = summary["open_ports"].(int) + h.OpenPorts
	}

	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	status := c.Query("status")
	notable := c.Query("notable")
	filtered := hosts[:0:0]
	for _, h := range hosts {
		if status != "" && h.Status != status {
			continue
		}
		if notable == "1" && len(h.Notable) == 0 {
			continue
		}
		if notable == "high" && h.MaxSeverity != "high" {
			continue
		}
		if q != "" {
			hay := strings.ToLower(h.IPAddress + " " + h.Hostname + " " + h.OSInfo + " " + strings.Join(h.Services, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		filtered = append(filtered, h)
	}

	sortKey, dir := c.DefaultQuery("sort", "ip"), c.DefaultQuery("dir", "asc")
	less := func(a, b *InventoryHost) bool {
		switch sortKey {
		case "open_ports":
			if a.OpenPorts != b.OpenPorts {
				return a.OpenPorts < b.OpenPorts
			}
		case "hostname":
			if a.Hostname != b.Hostname {
				return a.Hostname < b.Hostname
			}
		case "last_seen":
			if a.LastSeen != nil && b.LastSeen != nil && !a.LastSeen.Equal(*b.LastSeen) {
				return a.LastSeen.Before(*b.LastSeen)
			}
		case "severity":
			if severityRank(a.MaxSeverity) != severityRank(b.MaxSeverity) {
				return severityRank(a.MaxSeverity) < severityRank(b.MaxSeverity)
			}
		}
		return ipLess(a.IPAddress, b.IPAddress)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if dir == "desc" {
			return less(filtered[j], filtered[i])
		}
		return less(filtered[i], filtered[j])
	})

	total := len(filtered)
	start := offset(page, perPage)
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	items := filtered[start:end]
	if items == nil {
		items = []*InventoryHost{}
	}
	resp := paginatedResponse(items, int64(total), page, perPage)
	c.JSON(http.StatusOK, gin.H{"items": resp.Items, "total": resp.Total, "page": resp.Page, "per_page": resp.PerPage, "pages": resp.Pages, "summary": summary})
}

// ipLess orders dotted IPv4 numerically and falls back to string order.
func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) == 4 && len(pb) == 4 {
		for i := 0; i < 4; i++ {
			na, ea := strconv.Atoi(pa[i])
			nb, eb := strconv.Atoi(pb[i])
			if ea != nil || eb != nil {
				break
			}
			if na != nb {
				return na < nb
			}
		}
		return false
	}
	return a < b
}

type HostHistoryEntry struct {
	ReportID  uint       `json:"report_id"`
	TaskID    uint       `json:"task_id"`
	TaskName  string     `json:"task_name"`
	ScannedAt time.Time  `json:"scanned_at"`
	Status    string     `json:"status"`
	OpenPorts int        `json:"open_ports"`
	Opened    []HostPort `json:"opened"`
	Closed    []HostPort `json:"closed"`
}

// GetHost returns the current view of one IP plus its appearance history,
// with per-appearance port changes relative to the previous scan of the
// same task.
func GetHost(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)
	ip := c.Param("ip")

	rows := loadHostRows(u.ID, func(q *gorm.DB) *gorm.DB { return q.Where("host_findings.ip_address = ?", ip) })
	if len(rows) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Host not found"})
		return
	}

	latest := map[uint]bool{}
	var latestIDs []uint
	latestReportIDs(u.ID).Scan(&latestIDs)
	for _, id := range latestIDs {
		latest[id] = true
	}
	var currentRows []hostRow
	for _, r := range rows {
		if latest[r.ReportID] {
			currentRows = append(currentRows, r)
		}
	}
	present := len(currentRows) > 0
	if !present {
		currentRows = rows[:1]
	}
	current := aggregateHosts(currentRows)[0]
	first := firstSeenMap(u.ID)
	if t, ok := first[ip]; ok {
		current.FirstSeen = &t
	}
	ports := make([]HostPort, 0, len(current.ports))
	for _, p := range current.ports {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })

	// History newest first; changes computed against the previous row of the same task.
	history := make([]HostHistoryEntry, 0, len(rows))
	openSet := func(r hostRow) map[string]HostPort {
		m := map[string]HostPort{}
		for _, p := range r.Ports {
			if p.State == "open" {
				m[itoa(p.PortNumber)+"/"+p.Protocol] = toHostPort(p)
			}
		}
		return m
	}
	for i, r := range rows {
		cur := openSet(r)
		entry := HostHistoryEntry{ReportID: r.ReportID, TaskID: r.TaskID, TaskName: r.TaskName, ScannedAt: r.ScannedAt, Status: r.Status, OpenPorts: len(cur), Opened: []HostPort{}, Closed: []HostPort{}}
		for j := i + 1; j < len(rows); j++ {
			if rows[j].TaskID != r.TaskID {
				continue
			}
			prev := openSet(rows[j])
			for k, p := range cur {
				if _, ok := prev[k]; !ok {
					entry.Opened = append(entry.Opened, p)
				}
			}
			for k, p := range prev {
				if _, ok := cur[k]; !ok {
					entry.Closed = append(entry.Closed, p)
				}
			}
			break
		}
		sort.Slice(entry.Opened, func(a, b int) bool { return entry.Opened[a].Port < entry.Opened[b].Port })
		sort.Slice(entry.Closed, func(a, b int) bool { return entry.Closed[a].Port < entry.Closed[b].Port })
		history = append(history, entry)
	}

	c.JSON(http.StatusOK, gin.H{"host": current, "ports": ports, "present_in_latest": present, "history": history})
}
