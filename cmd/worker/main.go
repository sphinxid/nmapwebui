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
	"nmapwebui/internal/services"
)

func main() {
	cfg := config.Load()

	if _, err := db.Init(cfg, false); err != nil {
		fmt.Fprintf(os.Stderr, "Database init failed: %v\n", err)
		os.Exit(1)
	}

	rdb := services.InitRedis(cfg.RedisURL)
	ctx := context.Background()
	queueKey := services.ScanQueueKey()

	fmt.Println("Worker started, waiting for scan jobs...")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			result, err := rdb.BRPop(ctx, 0, queueKey).Result()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Queue error: %v\n", err)
				time.Sleep(2 * time.Second)
				continue
			}
			if len(result) < 2 {
				continue
			}
			runIDStr := result[1]
			runID, err := strconv.ParseUint(runIDStr, 10, 32)
			if err != nil {
				continue
			}

			var run models.ScanRun
			if err := db.DB.First(&run, runID).Error; err != nil {
				continue
			}

			lockKey := services.ScanLockKey(run.TaskID)
			token, ok := services.AcquireLock(ctx, lockKey, time.Hour)
			if !ok {
				fmt.Printf("Run %d: could not acquire lock for task %d\n", runID, run.TaskID)
				db.DB.Model(&run).Update("status", "failed")
				continue
			}

			fmt.Printf("Starting scan run %d (task %d)\n", runID, run.TaskID)
			if err := services.ExecuteScan(ctx, uint(runID), run.TaskID, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
			}
			services.ReleaseLock(ctx, lockKey, token)
		}
	}()

	<-quit
	fmt.Println("Worker shutting down...")
}
