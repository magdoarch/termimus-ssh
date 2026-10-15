package config

import (
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Port      string
	DBPath    string
	DataDir   string
	AuthToken string

	// AllowOpenMode permits running without a token (TERMIMUS_ALLOW_OPEN_MODE=1).
	// Only meant for local testing: anyone who can reach the port can then
	// overwrite or prune the stored revisions.
	AllowOpenMode bool
}

func Load() *Config {
	port := getEnv("PORT", "8080")
	dataDir := getEnv("DATA_DIR", "./data")
	dbPath := getEnv("DB_PATH", filepath.Join(dataDir, "sync.db"))
	authToken := strings.TrimSpace(getEnv("TERMIMUS_AUTH_TOKEN", ""))
	allowOpen := getEnv("TERMIMUS_ALLOW_OPEN_MODE", "") == "1"

	return &Config{
		Port:          port,
		DataDir:       dataDir,
		DBPath:        dbPath,
		AuthToken:     authToken,
		AllowOpenMode: allowOpen,
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
