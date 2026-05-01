package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	AppName              string
	SecretKey            string
	Debug                bool
	DatabaseURL          string
	RedisURL             string
	AccessTokenExpireMin int
	NmapReportsDir       string
	NmapWorkerPoolSize   int
	SuperAdminUsername    string
	SuperAdminPassword   string
	SuperAdminEmail      string
}

var DefaultProfiles = map[string]string{
	"quick_scan":       "-T4 -F",
	"intense_scan":     "-T4 -A -v",
	"intense_scan_Pn":  "-T4 -A -v -Pn",
	"ping_scan":        "-sn",
	"port_scan":        "-p 1-1000",
	"service_scan":     "-sV",
	"os_detection":     "-O",
	"comprehensive":    "-T4 -A -v -p- -Pn",
}

func Load() *Config {
	debug, _ := strconv.ParseBool(getEnv("DEBUG", "false"))
	expireMin, _ := strconv.Atoi(getEnv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))
	poolSize, _ := strconv.Atoi(getEnv("NMAP_WORKER_POOL_SIZE", "2"))

	return &Config{
		AppName:              getEnv("APP_NAME", "NmapWebUI"),
		SecretKey:            getEnv("SECRET_KEY", "dev-key-change-in-production"),
		Debug:                debug,
		DatabaseURL:          getEnv("DATABASE_URL", "instance/app.db"),
		RedisURL:             getEnv("REDIS_URL", "redis://localhost:6379/0"),
		AccessTokenExpireMin: expireMin,
		NmapReportsDir:       getEnv("NMAP_REPORTS_DIR", "instance/reports"),
		NmapWorkerPoolSize:   poolSize,
		SuperAdminUsername:    getEnv("SUPERADMIN_USERNAME", "admin"),
		SuperAdminPassword:   getEnv("SUPERADMIN_PASSWORD", "admin"),
		SuperAdminEmail:      getEnv("SUPERADMIN_EMAIL", "admin@localhost"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c *Config) TokenDuration() time.Duration {
	return time.Duration(c.AccessTokenExpireMin) * time.Minute
}
