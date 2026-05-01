package scheduler

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	"nmapwebui/internal/config"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
	"nmapwebui/internal/services"
)

func Start(cfg *config.Config) *cron.Cron {
	c := cron.New(cron.WithSeconds())
	c.AddFunc("0 * * * * *", func() { checkSchedules(cfg) })
	c.Start()
	return c
}

func checkSchedules(cfg *config.Config) {
	ctx := context.Background()
	lockKey := services.SchedulerLockKey()
	token, ok := services.AcquireLock(ctx, lockKey, 2*time.Minute)
	if !ok {
		return
	}
	defer services.ReleaseLock(ctx, lockKey, token)

	var tasks []models.ScanTask
	db.DB.Where("is_scheduled = ?", true).Find(&tasks)

	for _, task := range tasks {
		if !shouldTrigger(ctx, task) {
			continue
		}

		// Check DB for running scans
		var count int64
		db.DB.Model(&models.ScanRun{}).Where("task_id = ? AND status IN ?", task.ID, []string{"queued", "running"}).Count(&count)
		if count > 0 {
			continue
		}

		run := models.ScanRun{TaskID: task.ID, Status: "queued"}
		db.DB.Create(&run)

		services.GetRedis().LPush(ctx, services.ScanQueueKey(), run.ID)
		services.GetRedis().Set(ctx, services.ScheduleLastRunKey(task.ID), time.Now().UTC().Format(time.RFC3339), 0)
	}
}

func shouldTrigger(ctx context.Context, task models.ScanTask) bool {
	now := time.Now().UTC()
	lastStr, err := services.GetRedis().Get(ctx, services.ScheduleLastRunKey(task.ID)).Result()
	var last time.Time
	if err == nil {
		last, _ = time.Parse(time.RFC3339, lastStr)
	}

	switch task.ScheduleType {
	case "daily":
		return last.IsZero() || now.Sub(last) >= 22*time.Hour
	case "weekly":
		return last.IsZero() || now.Sub(last) >= 6*24*time.Hour
	case "monthly":
		return last.IsZero() || now.Sub(last) >= 28*24*time.Hour
	case "interval":
		minutes := 60
		if task.ScheduleData != "" {
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(task.ScheduleData), &data); err == nil {
				if m, ok := data["minutes"].(float64); ok {
					minutes = int(m)
				}
			}
		}
		return last.IsZero() || now.Sub(last) >= time.Duration(minutes)*time.Minute
	case "cron":
		if task.ScheduleData != "" {
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(task.ScheduleData), &data); err == nil {
				if expr, ok := data["expression"].(string); ok && expr != "" {
					parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
					schedule, err := parser.Parse(expr)
					if err == nil {
						next := schedule.Next(last)
						return now.After(next) || now.Equal(next)
					}
				}
			}
		}
	}
	return false
}

func formatScheduleData(data string) string {
	return strings.TrimSpace(data)
}

func parseInt(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
