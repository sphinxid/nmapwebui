package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/config"
	"nmapwebui/internal/db"
	"nmapwebui/internal/handlers"
	"nmapwebui/internal/middleware"
	"nmapwebui/internal/scheduler"
	"nmapwebui/internal/services"
)

func main() {
	cfg := config.Load()
	if !cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	os.MkdirAll(cfg.NmapReportsDir, 0755)

	if _, err := db.Init(cfg, true); err != nil {
		fmt.Fprintf(os.Stderr, "Database init failed: %v\n", err)
		os.Exit(1)
	}

	services.InitRedis(cfg.RedisURL)
	cronRunner := scheduler.Start(cfg)
	defer cronRunner.Stop()

	router := gin.Default()
	router.SetHTMLTemplate(handlers.LoadTemplates())

	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	router.Use(middleware.AuthOptional(cfg))
	router.Static("/static", "static")

	api := router.Group("/api")
	{
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok", "app": cfg.AppName})
		})
		api.GET("/server-time", func(c *gin.Context) {
			now := time.Now()
			c.JSON(http.StatusOK, gin.H{
				"time":     now.Format("2006-01-02T15:04:05Z07:00"),
				"timezone": now.Location().String(),
			})
		})

		api.POST("/auth/login", handlers.Login(cfg))
		api.POST("/auth/logout", handlers.Logout())

		authorized := api.Group("/")
		authorized.Use(middleware.AuthRequired(cfg))
		{
			authorized.GET("/targets", handlers.ListTargetGroups)
			authorized.POST("/targets", handlers.CreateTargetGroup)
			authorized.GET("/targets/:id", handlers.GetTargetGroup)
			authorized.DELETE("/targets/:id", handlers.DeleteTargetGroup)

			authorized.GET("/scans/profiles", handlers.ListScanProfiles)
			authorized.GET("/scans/tasks", handlers.ListScanTasks)
			authorized.POST("/scans/tasks", handlers.CreateScanTask)
			authorized.GET("/scans/tasks/:id", handlers.GetScanTask)
			authorized.PUT("/scans/tasks/:id", handlers.UpdateScanTask)
			authorized.DELETE("/scans/tasks/:id", handlers.DeleteScanTask)
			authorized.POST("/scans/tasks/:id/run", handlers.RunScanTask(cfg))
			authorized.GET("/scans/runs/:id", handlers.GetScanRun)

			authorized.POST("/schedules/tasks/:id/schedule", handlers.ScheduleTask)
			authorized.POST("/schedules/tasks/:id/unschedule", handlers.UnscheduleTask)

			authorized.GET("/reports", handlers.ListReports)
			authorized.GET("/reports/:id", handlers.GetReport)
			authorized.GET("/reports/:id/download/:format", handlers.DownloadReport)

			authorized.GET("/sse/scans/:run_id/events", handlers.ScanEvents)

			admin := authorized.Group("/admin")
			admin.Use(middleware.AdminRequired())
			{
				admin.GET("/users", handlers.ListUsers)
				admin.GET("/stats", handlers.GetStats)
				admin.POST("/users", handlers.CreateUser)
				admin.PUT("/users/:id", handlers.UpdateUser)
				admin.DELETE("/users/:id", handlers.DeleteUser)
			}
		}
	}

	router.GET("/", handlers.DashboardPage)
	router.GET("/login", handlers.LoginPage)
	router.GET("/targets", handlers.TargetsPage)
	router.GET("/tasks", handlers.TasksPage)
	router.GET("/tasks/create", handlers.TaskCreatePage)
	router.GET("/tasks/view/:id", handlers.TaskViewPage)
	router.GET("/tasks/run/:id", handlers.TaskRunPage)
	router.GET("/reports", handlers.ReportsPage)
	router.GET("/reports/:id", handlers.ReportViewPage)
	router.GET("/admin/users", handlers.AdminUsersPage)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		}
	}()

	fmt.Printf("Server running on http://0.0.0.0:%s\n", port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server shutdown error: %v\n", err)
	}
	fmt.Println("Server stopped")
}
