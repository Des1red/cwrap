package bootstrap

import (
	"cwrap/internal/model"
	"path/filepath"
	"time"
)

type Config struct {
	Version     string    `json:"version"`
	InstalledAt time.Time `json:"installed_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func configPath() string {
	return filepath.Join(model.ConfigDir(), "bootstrap", "config.json")
}
