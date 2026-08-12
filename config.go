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
	AgentSocket    string

	// KMS: auto-detected from which *_ENCRYPTED_KEY var is set.
	// If both are set, KMSProvider must be set to disambiguate.
	KMSProvider string // "aws" | "gcp" — explicit override (AGE_KMS_PROVIDER)

	// AWS KMS provider config.
	// Credentials resolved via: env vars → ~/.aws/credentials → IAM role.
	AWSKMSEncryptedKey string // base64 KMS ciphertext (AGE_AWS_KMS_ENCRYPTED_KEY)
	AWSKMSKeyID        string // optional key ID/ARN/alias (AWS_KMS_KEY_ID)
	AWSRegion          string // AWS region (AWS_REGION / AWS_DEFAULT_REGION)

	// GCP KMS provider config.
	// Credentials resolved via: GOOGLE_APPLICATION_CREDENTIALS → gcloud ADC → service account.
	GCPKMSEncryptedKey string // base64 KMS ciphertext (AGE_GCP_KMS_ENCRYPTED_KEY)
	GCPKMSKeyName      string // full resource name (GCP_KMS_KEY_NAME)
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
		AgentSocket:        os.Getenv("AGE_AGENT_SOCKET"),
		KMSProvider:        os.Getenv("AGE_KMS_PROVIDER"),
		AWSKMSEncryptedKey: os.Getenv("AGE_AWS_KMS_ENCRYPTED_KEY"),
		GCPKMSEncryptedKey: os.Getenv("AGE_GCP_KMS_ENCRYPTED_KEY"),
		AWSKMSKeyID:        os.Getenv("AWS_KMS_KEY_ID"),
		AWSRegion:          GetEnvOrDefault("AWS_REGION", os.Getenv("AWS_DEFAULT_REGION")),
		GCPKMSKeyName:      os.Getenv("GCP_KMS_KEY_NAME"),
	}
	return &Vault{Config: cfg}
}

func GetEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
