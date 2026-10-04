package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var redisClient *redis.Client

func InitRedis(addr string) *redis.Client {
	opts, err := redis.ParseURL(addr)
	if err != nil {
		// Fallback: treat as host:port
		opts = &redis.Options{Addr: addr}
	}
	redisClient = redis.NewClient(opts)
	return redisClient
}

func GetRedis() *redis.Client {
	return redisClient
}

func AcquireLock(ctx context.Context, key string, ttl time.Duration) (string, bool) {
	token := uuid.New().String()
	ok, err := redisClient.SetNX(ctx, key, token, ttl).Result()
	if err != nil || !ok {
		return "", false
	}
	return token, true
}

func ReleaseLock(ctx context.Context, key, token string) error {
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`
	_, err := redisClient.Eval(ctx, script, []string{key}, token).Result()
	return err
}

func IsLocked(ctx context.Context, key string) bool {
	val, err := redisClient.Get(ctx, key).Result()
	return err == nil && val != ""
}

func PublishEvent(ctx context.Context, channel string, payload string) error {
	return redisClient.Publish(ctx, channel, payload).Err()
}

func ScanLockKey(taskID uint) string {
	return fmt.Sprintf("nmapwebui:lock:task:%d", taskID)
}

func SchedulerLockKey() string {
	return "nmapwebui:lock:scheduler"
}

func ScanEventChannel(scanRunID uint) string {
	return fmt.Sprintf("nmapwebui:scan:%d:events", scanRunID)
}

func ScanQueueKey() string {
	return "nmapwebui:queue:scans"
}

func ScheduleLastRunKey(taskID uint) string {
	return fmt.Sprintf("nmapwebui:schedule:last_run:%d", taskID)
}

// ScanCancelKey is set by the API server to request cancellation of a run.
// The worker polls it while nmap is executing and kills the process when it
// appears. The key carries a TTL so stale requests expire on their own.
func ScanCancelKey(scanRunID uint) string {
	return fmt.Sprintf("nmapwebui:scan:%d:cancel", scanRunID)
}

// WorkerHeartbeatKey identifies a live worker process. Workers refresh it
// every few seconds with a short TTL so the API can count active workers.
func WorkerHeartbeatKey(workerID string) string {
	return "nmapwebui:worker:" + workerID
}

// WorkerHeartbeatPattern matches every worker heartbeat key.
func WorkerHeartbeatPattern() string {
	return "nmapwebui:worker:*"
}

// RequestCancel flags a scan run for cancellation.
func RequestCancel(ctx context.Context, scanRunID uint) error {
	return redisClient.Set(ctx, ScanCancelKey(scanRunID), "1", time.Hour).Err()
}

// CancelRequested reports whether a cancellation flag exists for the run.
func CancelRequested(ctx context.Context, scanRunID uint) bool {
	n, err := redisClient.Exists(ctx, ScanCancelKey(scanRunID)).Result()
	return err == nil && n > 0
}

// ClearCancel removes a run's cancellation flag.
func ClearCancel(ctx context.Context, scanRunID uint) {
	redisClient.Del(ctx, ScanCancelKey(scanRunID))
}

// CountWorkers returns the number of worker processes with a live heartbeat.
func CountWorkers(ctx context.Context) int {
	var cursor uint64
	count := 0
	for {
		keys, next, err := redisClient.Scan(ctx, cursor, WorkerHeartbeatPattern(), 100).Result()
		if err != nil {
			return count
		}
		count += len(keys)
		cursor = next
		if cursor == 0 {
			return count
		}
	}
}
