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

	// AWS KMS: decrypt the age private key via AWS KMS instead of reading it
	// from disk or an env var. Takes precedence over SecretKey/SecretKeyFile.
	// Credentials are resolved by the AWS SDK default chain
	// (env vars, ~/.aws/credentials, IAM instance/task role).
	AWSKMSEncryptedKey string // base64 KMS ciphertext (AGE_AWS_KMS_ENCRYPTED_KEY)
	AWSKMSKeyID        string // optional key ID/ARN/alias (AWS_KMS_KEY_ID)
	AWSRegion          string // AWS region (AWS_REGION / AWS_DEFAULT_REGION)
}

// Vault performs agevault operations using a given Config.
type Vault struct {
	Config *Config

	// KMSDecryptor overrides the KMS provider used by GetIdentity.
	// If nil, the provider is auto-selected from Config (currently AWS KMS).
	// Set this in tests to inject a mock without making real KMS calls.
	KMSDecryptor KeyDecryptor
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
		SecretKeyFile:  GetEnvOrDefault("AGE_SECRET_KEY_FILE", defaultKeyFile),
		Recipients:     os.Getenv("AGE_RECIPIENTS"),
		RecipientsFile: GetEnvOrDefault("AGE_RECIPIENTS_FILE", ".age.txt"),
		KeyServer:          os.Getenv("AGE_KEY_SERVER"),
		PubkeyExt:          GetEnvOrDefault("AGE_PUBKEY_EXT", "pub"),
		AWSKMSEncryptedKey: os.Getenv("AGE_AWS_KMS_ENCRYPTED_KEY"),
		AWSKMSKeyID:        os.Getenv("AWS_KMS_KEY_ID"),
		AWSRegion:          GetEnvOrDefault("AWS_REGION", os.Getenv("AWS_DEFAULT_REGION")),
	}
	return &Vault{Config: cfg}
}

func GetEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
