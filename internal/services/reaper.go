package services

import (
	"context"
	"fmt"
	"time"

	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

// ReapOnStartup marks any scan_runs stuck in "running" or "queued" as
// "failed". This is ONLY safe to call at worker startup — after a restart
// no nmap processes survive, so every active-looking run is orphaned.
//
// It also cleans up stale Redis task locks and drains the scan queue.
func ReapOnStartup(ctx context.Context) int {
	var orphans []models.ScanRun
	db.DB.Where("status IN ?", []string{"running", "queued"}).Find(&orphans)

	if len(orphans) == 0 {
		fmt.Println("[reaper] Startup: no orphaned scans found")
		return 0
	}

	now := time.Now()
	for _, run := range orphans {
		db.DB.Model(&run).Updates(map[string]interface{}{
			"status":        "failed",
			"completed_at":  now,
			"error_message": "Marked as failed by orphan reaper: worker restarted while scan was active",
		})

		// Release any stale task lock in Redis
		lockKey := ScanLockKey(run.TaskID)
		GetRedis().Del(ctx, lockKey)

		fmt.Printf("[reaper] Marked orphaned run %d (task %d, was %s) as failed\n", run.ID, run.TaskID, run.Status)
	}

	// Drain the Redis scan queue — any entries left refer to runs we
	// just marked failed, so workers should not pick them up.
	GetRedis().Del(ctx, ScanQueueKey())

	fmt.Printf("[reaper] Startup: cleaned up %d orphaned scan(s)\n", len(orphans))
	return len(orphans)
}
