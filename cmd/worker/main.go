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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queueKey := services.ScanQueueKey()

	poolSize := cfg.NmapWorkerPoolSize
	if poolSize < 1 {
		poolSize = 1
	}

	fmt.Printf("Worker started with pool size %d, waiting for scan jobs...\n", poolSize)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Semaphore to limit concurrent scans
	sem := make(chan struct{}, poolSize)

	go func() {
		for {
			result, err := rdb.BRPop(ctx, 5*time.Second, queueKey).Result()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// BRPop timeout is normal, just retry
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

			// Acquire a pool slot (blocks if all workers busy)
			sem <- struct{}{}

			go func(run models.ScanRun, runID uint64) {
				defer func() { <-sem }()

				lockKey := services.ScanLockKey(run.TaskID)
				token, ok := services.AcquireLock(ctx, lockKey, time.Hour)
				if !ok {
					fmt.Printf("Run %d: could not acquire lock for task %d\n", runID, run.TaskID)
					db.DB.Model(&run).Update("status", "failed")
					return
				}

				fmt.Printf("Starting scan run %d (task %d)\n", runID, run.TaskID)
				if err := services.ExecuteScan(ctx, uint(runID), run.TaskID, cfg); err != nil {
					fmt.Fprintf(os.Stderr, "Scan run %d error: %v\n", runID, err)
				}
				services.ReleaseLock(ctx, lockKey, token)
			}(run, runID)
		}
	}()

	<-quit
	fmt.Println("Worker shutting down...")
	cancel()
}
