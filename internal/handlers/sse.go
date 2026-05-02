package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
	"nmapwebui/internal/services"
)

func ScanEvents(c *gin.Context) {
	runIDStr := c.Param("run_id")
	runID, err := strconv.ParseUint(runIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid run ID"})
		return
	}
	user, _ := c.Get("user")
	u := user.(models.User)

	var run models.ScanRun
	if err := db.DB.Preload("Task").First(&run, runID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan run not found"})
		return
	}
	if run.Task.UserID != u.ID {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Scan run not found"})
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Streaming not supported"})
		return
	}

	ctx := c.Request.Context()
	channel := services.ScanEventChannel(uint(runID))
	pubsub := services.GetRedis().Subscribe(ctx, channel)
	defer pubsub.Close()

	// Send initial state
	fmt.Fprintf(c.Writer, "event: state\ndata: {\"status\":\"%s\",\"progress\":%d}\n\n", run.Status, run.Progress)
	flusher.Flush()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	msgCh := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-msgCh:
			eventType := extractEventType(msg.Payload)
			fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", eventType, msg.Payload)
			flusher.Flush()
			if containsTerminal(msg.Payload) {
				return
			}
		case <-ticker.C:
			fmt.Fprintf(c.Writer, "event: heartbeat\ndata: {\"ts\":%d}\n\n", time.Now().Unix())
			flusher.Flush()
		}
	}
}

func extractEventType(payload string) string {
	// Quick parse to get "type" field from JSON payload
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &m); err == nil {
		if t, ok := m["type"].(string); ok {
			return t
		}
	}
	return "message"
}

func containsTerminal(payload string) bool {
	return contains(payload, `"status":"completed"`) || contains(payload, `"status":"failed"`)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSub(s, substr))
}

func containsSub(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
