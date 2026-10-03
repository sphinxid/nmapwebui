package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/config"
	"nmapwebui/internal/services"
)

// Health reports whether the API, Redis and at least one worker are up. It is
// polled by the UI header indicator, so it must stay cheap.
func Health(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second)
		defer cancel()

		resp := gin.H{"status": "ok", "app": cfg.AppName, "redis": "ok", "workers": 0, "queue_depth": 0}

		rdb := services.GetRedis()
		if err := rdb.Ping(ctx).Err(); err != nil {
			resp["status"] = "degraded"
			resp["redis"] = "down"
			c.JSON(http.StatusOK, resp)
			return
		}

		workers := services.CountWorkers(ctx)
		resp["workers"] = workers
		if depth, err := rdb.LLen(ctx, services.ScanQueueKey()).Result(); err == nil {
			resp["queue_depth"] = depth
		}
		if workers == 0 {
			resp["status"] = "degraded"
		}
		c.JSON(http.StatusOK, resp)
	}
}
