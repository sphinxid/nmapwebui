package handlers

import (
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/models"
)

func LoadTemplates() *template.Template {
	tmpl := template.New("")
	err := filepath.Walk("templates", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".html" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("templates", path)
		name := strings.TrimSuffix(rel, filepath.Ext(rel))
		_, err = tmpl.New(name).Parse(string(b))
		return err
	})
	if err != nil {
		panic(err)
	}
	return tmpl
}

type PageData struct {
	User       *models.User
	Title      string
	ActivePage string
}

func setUser(c *gin.Context, data *PageData) {
	if u, ok := c.Get("user"); ok {
		user := u.(models.User)
		data.User = &user
	}
}

func requireUser(c *gin.Context) bool {
	_, ok := c.Get("user")
	if !ok {
		c.Redirect(http.StatusFound, "/login")
		c.Abort()
	}
	return ok
}

func renderPage(c *gin.Context, tmplName string, data PageData) {
	setUser(c, &data)
	c.HTML(http.StatusOK, tmplName, data)
}

func DashboardPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "main/index", PageData{Title: "Dashboard", ActivePage: "dashboard"})
}

func LoginPage(c *gin.Context) {
	if _, ok := c.Get("user"); ok {
		c.Redirect(http.StatusFound, "/")
		return
	}
	renderPage(c, "auth/login", PageData{Title: "Login", ActivePage: "login"})
}

func TargetsPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "targets/index", PageData{Title: "Target Groups", ActivePage: "targets"})
}

func TasksPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "tasks/index", PageData{Title: "Scan Tasks", ActivePage: "tasks"})
}

func TaskCreatePage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "tasks/create", PageData{Title: "Create Scan Task", ActivePage: "tasks-create"})
}

func TaskViewPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "tasks/view", PageData{Title: "View Task", ActivePage: "tasks-view"})
}

func TaskRunPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "tasks/run", PageData{Title: "Live Scan", ActivePage: "tasks-run"})
}

func ScanRunsPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "runs/index", PageData{Title: "All Scan Runs", ActivePage: "runs"})
}

func ReportsPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "reports/index", PageData{Title: "Reports", ActivePage: "reports"})
}

func ReportViewPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	renderPage(c, "reports/view", PageData{Title: "Report", ActivePage: "reports-view"})
}

func AdminUsersPage(c *gin.Context) {
	if !requireUser(c) {
		return
	}
	u, _ := c.Get("user")
	user := u.(models.User)
	if !user.IsAdmin() {
		c.Redirect(http.StatusFound, "/")
		c.Abort()
		return
	}
	renderPage(c, "admin/users", PageData{Title: "User Management", ActivePage: "admin-users"})
}
