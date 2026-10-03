package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nmapwebui/internal/config"
	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

func BuildNmapArgs(task models.ScanTask, cfg *config.Config) []string {
	args := []string{"-v"}
	if task.ScanProfile != "" {
		if profileArgs, ok := config.DefaultProfiles[task.ScanProfile]; ok {
			args = append(args, strings.Fields(profileArgs)...)
		}
	} else if task.CustomArgs != "" {
		args = append(args, strings.Fields(task.CustomArgs)...)
	} else {
		args = append(args, "-T4", "-F")
	}
	return args
}

func GetTargets(task models.ScanTask) []string {
	var targets []string
	for _, tg := range task.TargetGroups {
		for _, t := range tg.Targets {
			targets = append(targets, t.Value)
		}
	}
	return targets
}

func ExecuteScan(ctx context.Context, runID, taskID uint, cfg *config.Config) error {
	var task models.ScanTask
	if err := db.DB.Preload("TargetGroups.Targets").First(&task, taskID).Error; err != nil {
		return err
	}

	targets := GetTargets(task)
	if len(targets) == 0 {
		failRun(runID, "No targets specified")
		return nil
	}

	args := BuildNmapArgs(task, cfg)

	timestamp := time.Now().UTC().Format("20060102_150405")
	scanID := fmt.Sprintf("scan_%d_%s", runID, timestamp)

	reportsDir := cfg.NmapReportsDir
	os.MkdirAll(reportsDir, 0755)

	xmlPath := filepath.Join(reportsDir, scanID+".xml")
	normalPath := filepath.Join(reportsDir, scanID+".txt")

	args = append(args, "-oX", xmlPath, "-oN", normalPath, "--stats-every", "5s")
	args = append(args, targets...)

	// A cancel request may have arrived while the run sat in the queue.
	if CancelRequested(ctx, runID) {
		cancelRun(ctx, runID)
		return nil
	}

	publish(ctx, runID, "status", map[string]interface{}{
		"status": "starting", "message": "Starting nmap scan",
	})

	// runCtx is cancelled either when the worker shuts down or when the API
	// flags this run for cancellation; CommandContext then kills nmap.
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	cancelled := false
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if CancelRequested(ctx, runID) {
					cancelled = true
					stopRun()
					return
				}
			}
		}
	}()

	cmd := exec.CommandContext(runCtx, "nmap", args...)
	// nmap writes progress stats to stderr, so we need to capture both
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		failRun(runID, fmt.Sprintf("stdout pipe: %v", err))
		return nil
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		failRun(runID, fmt.Sprintf("stderr pipe: %v", err))
		return nil
	}

	if err := cmd.Start(); err != nil {
		failRun(runID, fmt.Sprintf("start nmap: %v", err))
		return nil
	}

	pid := cmd.Process.Pid
	now := time.Now()
	if err := db.DB.Model(&models.ScanRun{}).Where("id = ?", runID).Updates(map[string]interface{}{
		"status": "running", "started_at": now, "nmap_p_id": pid,
	}).Error; err != nil {
		fmt.Fprintf(os.Stderr, "[nmap] Run %d: failed to update started_at/pid: %v\n", runID, err)
	}

	publish(ctx, runID, "status", map[string]interface{}{
		"status": "running", "pid": pid,
	})

	// Scan stderr in background for progress updates (nmap writes stats there)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, "About") && strings.Contains(line, "% done") {
				parseAndPublishProgress(ctx, runID, line)
			}
		}
	}()

	// Drain stdout so the process doesn't block
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "About") && strings.Contains(line, "% done") {
			parseAndPublishProgress(ctx, runID, line)
		}
	}

	waitErr := cmd.Wait()
	stopRun()
	if cancelled {
		cancelRun(ctx, runID)
		return nil
	}
	if waitErr != nil {
		failRun(runID, fmt.Sprintf("nmap exited with error: %v", waitErr))
		return nil
	}

	if _, err := os.Stat(xmlPath); os.IsNotExist(err) {
		failRun(runID, "Nmap completed but no XML output found")
		return nil
	}

	ClearCancel(ctx, runID)
	db.DB.Model(&models.ScanRun{}).Where("id = ?", runID).Updates(map[string]interface{}{
		"status": "completed", "completed_at": time.Now(), "progress": 100,
	})

	publish(ctx, runID, "status", map[string]interface{}{
		"status": "completed", "message": "Scan completed successfully",
	})

	if err := CreateReportFromXML(runID, xmlPath, normalPath); err != nil {
		publish(ctx, runID, "status", map[string]interface{}{
			"status": "failed", "message": fmt.Sprintf("Report creation failed: %v", err),
		})
	}

	return nil
}

func parseAndPublishProgress(ctx context.Context, runID uint, line string) {
	start := strings.Index(line, "About ")
	end := strings.Index(line, "% done")
	if start == -1 || end == -1 || end <= start+6 {
		return
	}
	pctStr := strings.TrimSpace(line[start+6 : end])
	if pct, err := strconv.ParseFloat(pctStr, 64); err == nil {
		pctInt := int(pct)
		db.DB.Model(&models.ScanRun{}).Where("id = ?", runID).Update("progress", pctInt)
		publish(ctx, runID, "progress", map[string]interface{}{"progress": pctInt})
	}
}

// cancelRun marks a run as cancelled by user request and notifies listeners.
func cancelRun(ctx context.Context, runID uint) {
	db.DB.Model(&models.ScanRun{}).Where("id = ?", runID).Updates(map[string]interface{}{
		"status": "cancelled", "completed_at": time.Now(), "error_message": "Cancelled by user",
	})
	ClearCancel(ctx, runID)
	publish(ctx, runID, "status", map[string]interface{}{
		"status": "cancelled", "message": "Scan cancelled by user",
	})
}

func failRun(runID uint, message string) {
	db.DB.Model(&models.ScanRun{}).Where("id = ?", runID).Updates(map[string]interface{}{
		"status": "failed", "completed_at": time.Now(), "error_message": message,
	})
}

func publish(ctx context.Context, runID uint, eventType string, payload map[string]interface{}) {
	payload["type"] = eventType
	data, _ := json.Marshal(payload)
	PublishEvent(ctx, ScanEventChannel(runID), string(data))
}
