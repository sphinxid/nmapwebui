package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"nmapwebui/internal/config"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
	"nmapwebui/internal/scheduler"
	"nmapwebui/internal/services"
)

func main() {
	cfg := config.Load()

	if _, err := db.Init(cfg, false); err != nil {
		fmt.Fprintf(os.Stderr, "Database init failed: %v\n", err)
		os.Exit(1)
	}

	rdb := services.InitRedis(cfg.RedisURL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queueKey := services.ScanQueueKey()

	poolSize := cfg.NmapWorkerPoolSize
	if poolSize < 1 {
		poolSize = 1
	}

	fmt.Printf("Worker started with pool size %d, waiting for scan jobs...\n", poolSize)

	// On startup, mark any leftover running/queued scans as failed.
	// After a restart no nmap processes survive, so they are all orphaned.
	services.ReapOnStartup(ctx)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Launch pool workers that each compete for jobs from Redis.
	// Jobs stay in Redis until a worker is actually free, so nothing
	// is lost if the worker restarts while the pool is saturated.
	for i := 0; i < poolSize; i++ {
		go func(workerID int) {
			for {
				result, err := rdb.BRPop(ctx, 5*time.Second, queueKey).Result()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				if len(result) < 2 {
					continue
				}
				runID, err := strconv.ParseUint(result[1], 10, 32)
				if err != nil {
					continue
				}

				var run models.ScanRun
				if err := db.DB.First(&run, runID).Error; err != nil {
					fmt.Fprintf(os.Stderr, "[worker %d] Run %d: DB load failed: %v\n", workerID, runID, err)
					continue
				}

				// Skip runs that were already reaped or otherwise finished.
				if run.Status != "queued" && run.Status != "running" {
					continue
				}

				// Mark as running immediately so the dashboard reflects it.
				// Retry a few times in case SQLite returns BUSY.
				for attempt := 0; attempt < 3; attempt++ {
					if err := db.DB.Model(&run).Update("status", "running").Error; err != nil {
						fmt.Fprintf(os.Stderr, "[worker %d] Run %d: status update to running failed (attempt %d): %v\n", workerID, runID, attempt+1, err)
						time.Sleep(200 * time.Millisecond)
						continue
					}
					break
				}

				// Update schedule last_run in the DB so the scheduler knows this trigger was fulfilled
				var task models.ScanTask
				if db.DB.First(&task, run.TaskID).Error == nil && task.IsScheduled {
					now := time.Now().UTC()
					db.DB.Model(&task).Update("schedule_last_run", now)
				}

				lockKey := services.ScanLockKey(run.TaskID)
				token, ok := services.AcquireLock(ctx, lockKey, time.Hour)
				if !ok {
					fmt.Printf("Run %d: could not acquire lock for task %d\n", runID, run.TaskID)
					db.DB.Model(&run).Update("status", "failed")
					continue
				}

				fmt.Printf("[worker %d] Starting scan run %d (task %d)\n", workerID, runID, run.TaskID)
				if err := services.ExecuteScan(ctx, uint(runID), run.TaskID, cfg); err != nil {
					fmt.Fprintf(os.Stderr, "[worker %d] Scan run %d error: %v\n", workerID, runID, err)
				}
				services.ReleaseLock(ctx, lockKey, token)

				// Check if this scheduled task missed any trigger windows
				// while the worker pool was full and re-queue if needed.
				scheduler.RecoverMissedSchedule(run.TaskID)
			}
		}(i)
	}

	<-quit
	fmt.Println("Worker shutting down...")
	cancel()
}
