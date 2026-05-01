package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

func ListReports(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(models.User)

	var reports []models.ScanReport
	db.DB.Preload("Hosts.Ports").Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_tasks.user_id = ?", u.ID).Find(&reports)
	c.JSON(http.StatusOK, reports)
}

func GetReport(c *gin.Context) {
	id := c.Param("id")
	user, _ := c.Get("user")
	u := user.(models.User)

	var report models.ScanReport
	if err := db.DB.Preload("Hosts.Ports").Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_reports.id = ? AND scan_tasks.user_id = ?", id, u.ID).First(&report).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Report not found"})
		return
	}
	c.JSON(http.StatusOK, report)
}

func DownloadReport(c *gin.Context) {
	id := c.Param("id")
	format := c.Param("format")
	user, _ := c.Get("user")
	u := user.(models.User)

	var report models.ScanReport
	if err := db.DB.Preload("Hosts.Ports").Joins("JOIN scan_runs ON scan_runs.id = scan_reports.scan_run_id").
		Joins("JOIN scan_tasks ON scan_tasks.id = scan_runs.task_id").
		Where("scan_reports.id = ? AND scan_tasks.user_id = ?", id, u.ID).First(&report).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Report not found"})
		return
	}

	switch format {
	case "xml":
		if report.XMLReportPath != "" {
			c.FileAttachment(report.XMLReportPath, "report_"+id+".xml")
			return
		}
	case "txt":
		if report.NormalReportPath != "" {
			c.FileAttachment(report.NormalReportPath, "report_"+id+".txt")
			return
		}
	case "html":
		html, err := renderHTMLReport(report)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to generate HTML report"})
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"report_%s.html\"", id))
		c.String(http.StatusOK, html)
		return
	case "pdf":
		html, err := renderHTMLReport(report)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to generate report"})
			return
		}
		pdf, err := htmlToPDF(html)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": fmt.Sprintf("PDF generation failed: %v", err)})
			return
		}
		c.Header("Content-Type", "application/pdf")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"report_%s.pdf\"", id))
		c.Data(http.StatusOK, "application/pdf", pdf)
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"detail": "Report format not available"})
}

func renderHTMLReport(report models.ScanReport) (string, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"stateColor": func(state string) string {
			switch state {
			case "open":
				return "#10b981"
			case "filtered":
				return "#f59e0b"
			case "closed":
				return "#6b7280"
			default:
				return "#6b7280"
			}
		},
		"statusColor": func(status string) string {
			if status == "up" {
				return "#10b981"
			}
			return "#ef4444"
		},
	}).Parse(htmlReportTemplate)
	if err != nil {
		return "", err
	}

	type HostStats struct {
		TotalHosts    int
		HostsUp       int
		OpenPorts     int
		TotalServices int
	}

	hostsUp := 0
	openPorts := 0
	services := make(map[string]bool)
	for _, h := range report.Hosts {
		if h.Status == "up" {
			hostsUp++
		}
		for _, p := range h.Ports {
			if p.State == "open" {
				openPorts++
				if p.Service != "" {
					services[p.Service] = true
				}
			}
		}
	}

	data := struct {
		Report    models.ScanReport
		Stats     HostStats
		Generated string
	}{
		Report: report,
		Stats: HostStats{
			TotalHosts:    len(report.Hosts),
			HostsUp:       hostsUp,
			OpenPorts:     openPorts,
			TotalServices: len(services),
		},
		Generated: time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func htmlToPDF(htmlContent string) ([]byte, error) {
	tmpDir := os.TempDir()
	htmlFile := filepath.Join(tmpDir, fmt.Sprintf("report_%d.html", time.Now().UnixNano()))
	pdfFile := filepath.Join(tmpDir, fmt.Sprintf("report_%d.pdf", time.Now().UnixNano()))
	defer os.Remove(htmlFile)
	defer os.Remove(pdfFile)

	if err := os.WriteFile(htmlFile, []byte(htmlContent), 0644); err != nil {
		return nil, fmt.Errorf("write temp HTML: %w", err)
	}

	cmd := exec.Command("wkhtmltopdf",
		"--page-size", "A4",
		"--margin-top", "15mm",
		"--margin-bottom", "15mm",
		"--margin-left", "10mm",
		"--margin-right", "10mm",
		"--encoding", "UTF-8",
		"--enable-local-file-access",
		"--no-stop-slow-scripts",
		"--quiet",
		htmlFile, pdfFile,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("wkhtmltopdf: %v (output: %s)", err, string(output))
	}

	return os.ReadFile(pdfFile)
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NmapWebUI Scan Report #{{.Report.ID}}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #111827; color: #e5e7eb; line-height: 1.6; padding: 40px 20px; }
.container { max-width: 900px; margin: 0 auto; }
.header { text-align: center; margin-bottom: 40px; padding-bottom: 30px; border-bottom: 2px solid #374151; }
.header h1 { font-size: 28px; color: #10b981; margin-bottom: 8px; }
.header .subtitle { color: #9ca3af; font-size: 14px; }
.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 40px; }
.stat-card { background: #1f2937; border: 1px solid #374151; border-radius: 12px; padding: 20px; text-align: center; }
.stat-card .number { font-size: 32px; font-weight: 700; }
.stat-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #9ca3af; margin-top: 4px; }
.host-card { background: #1f2937; border: 1px solid #374151; border-radius: 12px; margin-bottom: 24px; overflow: hidden; }
.host-header { padding: 20px 24px; border-bottom: 1px solid #374151; display: flex; align-items: center; justify-content: space-between; }
.host-ip { font-size: 18px; font-weight: 700; font-family: 'SF Mono', 'Fira Code', monospace; color: #f9fafb; }
.host-hostname { color: #9ca3af; font-size: 13px; margin-top: 2px; }
.host-badges { display: flex; gap: 8px; align-items: center; }
.badge { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.badge-up { background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3); }
.badge-down { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }
.os-info { color: #60a5fa; font-size: 12px; }
table { width: 100%; border-collapse: collapse; }
th { background: rgba(55,65,81,0.5); padding: 12px 20px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #9ca3af; font-weight: 600; }
td { padding: 10px 20px; border-top: 1px solid rgba(55,65,81,0.5); font-size: 14px; }
tr:hover { background: rgba(55,65,81,0.2); }
.port-num { font-family: 'SF Mono', 'Fira Code', monospace; font-weight: 600; color: #f9fafb; }
.port-proto { color: #6b7280; font-size: 12px; }
.state-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
.state-open { background: rgba(16,185,129,0.15); color: #10b981; }
.state-filtered { background: rgba(245,158,11,0.15); color: #f59e0b; }
.state-closed { background: rgba(107,114,128,0.15); color: #6b7280; }
.no-ports { padding: 20px 24px; color: #6b7280; font-style: italic; }
.footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #374151; color: #6b7280; font-size: 12px; }
@media print {
    body { background: white; color: #111; padding: 20px; }
    .container { max-width: 100%; }
    .header { border-bottom-color: #e5e7eb; }
    .header h1 { color: #059669; }
    .stat-card { background: #f9fafb; border-color: #e5e7eb; }
    .stat-card .number { color: #111; }
    .host-card { background: #f9fafb; border-color: #e5e7eb; }
    .host-header { border-bottom-color: #e5e7eb; }
    .host-ip { color: #111; }
    th { background: #f3f4f6; color: #374151; }
    td { border-top-color: #e5e7eb; color: #374151; }
    .port-num { color: #111; }
    .footer { border-top-color: #e5e7eb; }
}
@media (max-width: 640px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .host-header { flex-direction: column; align-items: flex-start; gap: 8px; }
}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>&#x1f5a5; NmapWebUI Scan Report</h1>
        <p class="subtitle">Report #{{.Report.ID}} &bull; Generated {{.Generated}}</p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="number" style="color: #10b981">{{.Stats.TotalHosts}}</div>
            <div class="label">Total Hosts</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: #22c55e">{{.Stats.HostsUp}}</div>
            <div class="label">Hosts Up</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: #f59e0b">{{.Stats.OpenPorts}}</div>
            <div class="label">Open Ports</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: #60a5fa">{{.Stats.TotalServices}}</div>
            <div class="label">Services</div>
        </div>
    </div>

    {{range .Report.Hosts}}
    <div class="host-card">
        <div class="host-header">
            <div>
                <div class="host-ip">{{.IPAddress}}</div>
                {{if .Hostname}}<div class="host-hostname">{{.Hostname}}</div>{{end}}
            </div>
            <div class="host-badges">
                <span class="badge {{if eq .Status "up"}}badge-up{{else}}badge-down{{end}}">&#x25CF; {{.Status}}</span>
                {{if .OSInfo}}<span class="os-info">{{.OSInfo}}</span>{{end}}
            </div>
        </div>
        {{if .Ports}}
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
                {{range .Ports}}
                <tr>
                    <td><span class="port-num">{{.PortNumber}}</span><span class="port-proto">/{{.Protocol}}</span></td>
                    <td><span class="state-badge {{if eq .State "open"}}state-open{{else if eq .State "filtered"}}state-filtered{{else}}state-closed{{end}}">{{.State}}</span></td>
                    <td>{{if .Service}}{{.Service}}{{else}}-{{end}}</td>
                    <td style="color: #9ca3af; font-size: 13px;">{{if .Version}}{{.Version}}{{else}}-{{end}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{else}}
        <div class="no-ports">No port information available</div>
        {{end}}
    </div>
    {{end}}

    <div class="footer">
        Generated by NmapWebUI &bull; {{.Generated}}
    </div>
</div>
</body>
</html>`
