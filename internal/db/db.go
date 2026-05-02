package db

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"nmapwebui/internal/config"
	"nmapwebui/internal/models"
)

var DB *gorm.DB

// Init opens the database and runs migrations. If seed is true, it also seeds
// the superadmin account (should only be true for the server process).
func Init(cfg *config.Config, seed bool) (*gorm.DB, error) {
	dsn := cfg.DatabaseURL
	if !strings.Contains(dsn, "://") {
		dsn = filepath.Clean(dsn)
		if err := os.MkdirAll(filepath.Dir(dsn), 0755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	logLevel := logger.Silent
	if cfg.Debug {
		logLevel = logger.Info
	}

	// Enable WAL mode and set a busy timeout so concurrent access from the
	// server and worker processes doesn't fail with SQLITE_BUSY.
	if !strings.Contains(dsn, "?") {
		dsn += "?_journal_mode=WAL&_busy_timeout=5000"
	} else {
		dsn += "&_journal_mode=WAL&_busy_timeout=5000"
	}

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Enforce WAL mode at the connection level (some drivers ignore DSN pragmas)
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")

	if err := db.AutoMigrate(
		&models.User{},
		&models.TargetGroup{},
		&models.Target{},
		&models.ScanTask{},
		&models.ScanRun{},
		&models.ScanReport{},
		&models.HostFinding{},
		&models.PortFinding{},
		&models.SystemSettings{},
	); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	DB = db

	// Backfill schedule_last_run for existing scheduled tasks that have
	// a NULL value (i.e. the column was just added by AutoMigrate).
	// Set it to now so they don't all fire immediately on upgrade.
	db.Exec("UPDATE scan_tasks SET schedule_last_run = ? WHERE is_scheduled = 1 AND schedule_last_run IS NULL", time.Now().UTC())

	if seed {
		seedSuperAdmin(cfg)
	}
	return db, nil
}

func seedSuperAdmin(cfg *config.Config) {
	var count int64
	DB.Model(&models.User{}).Where("role = ?", "superadmin").Count(&count)
	if count > 0 {
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.SuperAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to hash superadmin password: %v\n", err)
		return
	}

	user := models.User{
		Username:     cfg.SuperAdminUsername,
		Email:        cfg.SuperAdminEmail,
		PasswordHash: string(hash),
		Role:         "superadmin",
		Active:       true,
		Timezone:     "UTC",
	}
	if err := DB.Create(&user).Error; err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create superadmin: %v\n", err)
		return
	}
	fmt.Printf("Superadmin user '%s' created\n", cfg.SuperAdminUsername)
}
