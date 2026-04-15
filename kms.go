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
