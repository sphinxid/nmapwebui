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
