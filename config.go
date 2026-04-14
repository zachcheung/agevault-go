// Package agevault provides tools for managing age-encrypted secrets.
package agevault

import (
	"os"
	"path/filepath"
)

// Config holds agevault configuration loaded from environment variables.
type Config struct {
	SecretKey      string
	SecretKeyFile  string
	Recipients     string
	RecipientsFile string
	KeyServer      string
	PubkeyExt      string
}

// Vault performs agevault operations using a given Config.
type Vault struct {
	Config *Config
}

// NewVault initializes a Vault by loading configuration from environment variables.
func NewVault() *Vault {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback if home dir cannot be determined.
		homeDir = "."
	}
	defaultKeyFile := filepath.Join(homeDir, ".age", "age.key")
	cfg := &Config{
		SecretKey:      os.Getenv("AGE_SECRET_KEY"),
		SecretKeyFile:  getEnvOrDefault("AGE_SECRET_KEY_FILE", defaultKeyFile),
		Recipients:     os.Getenv("AGE_RECIPIENTS"),
		RecipientsFile: getEnvOrDefault("AGE_RECIPIENTS_FILE", ".age.txt"),
		KeyServer:      os.Getenv("AGE_KEY_SERVER"),
		PubkeyExt:      getEnvOrDefault("AGE_PUBKEY_EXT", "pub"),
	}
	return &Vault{Config: cfg}
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
