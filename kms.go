package agevault

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
)

// KeyDecryptor decrypts a KMS-encrypted blob and returns the plaintext age private key bytes.
// Implement this interface to add support for a new KMS provider (e.g. GCP KMS, HashiCorp Vault).
type KeyDecryptor interface {
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// KeyEncryptor encrypts plaintext bytes with KMS and returns the raw ciphertext.
type KeyEncryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
}

// resolveKMS returns the active KMS provider name and its base64 ciphertext.
// Auto-detects from which *_ENCRYPTED_KEY vars are set; requires AGE_KMS_PROVIDER
// when both are set. Returns ("", "", nil) when no KMS is configured.
func (v *Vault) resolveKMS() (provider, ciphertext string, err error) {
	hasAWS := v.Config.AWSKMSEncryptedKey != ""
	hasGCP := v.Config.GCPKMSEncryptedKey != ""

	if !hasAWS && !hasGCP {
		return "", "", nil
	}

	p := v.Config.KMSProvider
	if p == "" {
		if hasAWS && hasGCP {
			return "", "", fmt.Errorf("both AGE_AWS_KMS_ENCRYPTED_KEY and AGE_GCP_KMS_ENCRYPTED_KEY are set; set AGE_KMS_PROVIDER=aws or AGE_KMS_PROVIDER=gcp to disambiguate")
		}
		if hasAWS {
			p = "aws"
		} else {
			p = "gcp"
		}
	}

	switch p {
	case "aws":
		if !hasAWS {
			return "", "", fmt.Errorf("AGE_KMS_PROVIDER=aws but AGE_AWS_KMS_ENCRYPTED_KEY is not set")
		}
		return "aws", v.Config.AWSKMSEncryptedKey, nil
	case "gcp":
		if !hasGCP {
			return "", "", fmt.Errorf("AGE_KMS_PROVIDER=gcp but AGE_GCP_KMS_ENCRYPTED_KEY is not set")
		}
		return "gcp", v.Config.GCPKMSEncryptedKey, nil
	default:
		return "", "", fmt.Errorf("unknown KMS provider %q (supported: aws, gcp)", p)
	}
}

// newKMSDecryptor returns the KMS decryptor for the given provider name.
func (v *Vault) newKMSDecryptor(provider string) (KeyDecryptor, error) {
	switch provider {
	case "aws":
		return &awsKMSDecryptor{keyID: v.Config.AWSKMSKeyID, region: v.Config.AWSRegion}, nil
	case "gcp":
		return &gcpKMSDecryptor{keyName: v.Config.GCPKMSKeyName}, nil
	default:
		return nil, fmt.Errorf("unknown KMS provider %q", provider)
	}
}

// newKMSEncryptor returns the KMS encryptor for the given provider name.
// For AWS, AWS_KMS_KEY_ID must be set (required for encrypt; optional for decrypt).
func (v *Vault) newKMSEncryptor(provider string) (KeyEncryptor, error) {
	switch provider {
	case "aws":
		if v.Config.AWSKMSKeyID == "" {
			return nil, fmt.Errorf("AWS_KMS_KEY_ID is required for --kms-out")
		}
		return &awsKMSDecryptor{keyID: v.Config.AWSKMSKeyID, region: v.Config.AWSRegion}, nil
	case "gcp":
		return &gcpKMSDecryptor{keyName: v.Config.GCPKMSKeyName}, nil
	default:
		return nil, fmt.Errorf("unknown KMS provider %q", provider)
	}
}

// decryptIdentityFromKMS decodes a base64 KMS ciphertext, calls the decryptor,
// and parses the resulting plaintext as an age identity.
func decryptIdentityFromKMS(ctx context.Context, decryptor KeyDecryptor, b64Ciphertext string) (age.Identity, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode KMS ciphertext: %w", err)
	}
	plaintext, err := decryptor.Decrypt(ctx, ciphertext)
	if err != nil {
		return nil, err
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(plaintext)))
	if err != nil {
		return nil, fmt.Errorf("parse KMS-decrypted key: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities in KMS-decrypted key")
	}
	return ids[0], nil
}
