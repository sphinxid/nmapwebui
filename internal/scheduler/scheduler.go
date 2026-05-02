package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
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

	// Cache user timezones so we only look them up once per check cycle.
	userTZCache := map[uint]*time.Location{}

	for _, task := range tasks {
		tz := getUserTZ(task.UserID, userTZCache)
		if !shouldTrigger(task, tz) {
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

		// Persist last_run in the DB immediately so the scheduler won't
		// re-trigger this task on the next tick even if the worker hasn't
		// picked it up yet. Durable — survives Redis/container restarts.
		now := time.Now().UTC()
		db.DB.Model(&task).Update("schedule_last_run", now)

		services.GetRedis().LPush(ctx, services.ScanQueueKey(), run.ID)
	}
}

// getUserTZ resolves a user's IANA timezone from the DB, with a cache.
func getUserTZ(userID uint, cache map[uint]*time.Location) *time.Location {
	if loc, ok := cache[userID]; ok {
		return loc
	}
	var user models.User
	if err := db.DB.Select("timezone").First(&user, userID).Error; err == nil && user.Timezone != "" {
		if loc, err := time.LoadLocation(user.Timezone); err == nil {
			cache[userID] = loc
			return loc
		}
	}
	cache[userID] = time.UTC
	return time.UTC
}

// shouldTrigger checks whether a scheduled task should fire now.
// Cron expressions are evaluated in the task owner's timezone so that
// schedule times match what the user sees on the frontend.
// last_run is read from the ScanTask.ScheduleLastRun DB column (durable).
func shouldTrigger(task models.ScanTask, userTZ *time.Location) bool {
	now := time.Now().In(userTZ)
	var last time.Time
	if task.ScheduleLastRun != nil {
		last = *task.ScheduleLastRun
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
						// Evaluate cron in the user's timezone so "8 57"
						// means 08:57 in the user's locale.
						lastInTZ := last.In(userTZ)
						next := schedule.Next(lastInTZ)
						return now.After(next) || now.Equal(next)
					}
				}
			}
		}
	}
	return false
}

// RecoverMissedSchedule checks whether a scheduled task missed any trigger
// windows while the worker pool was full. If so it creates a new queued run
// and pushes it to Redis so the next free worker picks it up immediately.
// Call this from the worker right after a scheduled task finishes.
func RecoverMissedSchedule(taskID uint) {
	ctx := context.Background()
	var task models.ScanTask
	if err := db.DB.First(&task, taskID).Error; err != nil || !task.IsScheduled {
		return
	}

	tz := getUserTZ(task.UserID, map[uint]*time.Location{})
	if !shouldTrigger(task, tz) {
		return
	}

	// Don't queue if there is already a pending run
	var count int64
	db.DB.Model(&models.ScanRun{}).Where("task_id = ? AND status IN ?", task.ID, []string{"queued", "running"}).Count(&count)
	if count > 0 {
		return
	}

	run := models.ScanRun{TaskID: task.ID, Status: "queued"}
	db.DB.Create(&run)
	services.GetRedis().LPush(ctx, services.ScanQueueKey(), run.ID)
	fmt.Printf("[scheduler] Recovered missed schedule for task %d -> run %d\n", taskID, run.ID)
}

func formatScheduleData(data string) string {
	return strings.TrimSpace(data)
}

func parseInt(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
