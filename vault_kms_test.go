package agevault_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	agevault "github.com/zachcheung/agevault-go"
)

// mockDecryptor implements KeyDecryptor and records whether it was called.
type mockDecryptor struct {
	plaintext []byte
	called    bool
}

func (m *mockDecryptor) Decrypt(_ context.Context, _ []byte) ([]byte, error) {
	m.called = true
	return m.plaintext, nil
}

// runKMSIntegrationTest encrypts to recipients (AGE_RECIPIENTS or AGE_RECIPIENTS_FILE),
// then decrypts via KMS to verify the KMS-protected private key can decrypt it.
// AGE_KMS_PROVIDER must be set by the caller via t.Setenv before invoking this helper.
func runKMSIntegrationTest(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	plainFile := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(plainFile, []byte("hello from kms\n"), 0644); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	// Encrypt to recipients (AGE_RECIPIENTS or AGE_RECIPIENTS_FILE) — no KMS involved.
	if err := agevault.NewVault().Encrypt(false, plainFile); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	os.Remove(plainFile)

	// Decrypt using KMS — proves the KMS-protected private key matches AGE_RECIPIENTS.
	if err := agevault.NewVault().Decrypt(plainFile + ".age"); err != nil {
		t.Fatalf("Decrypt via KMS: %v", err)
	}

	got, err := os.ReadFile(plainFile)
	if err != nil {
		t.Fatalf("read decrypted file: %v", err)
	}
	if string(got) != "hello from kms\n" {
		t.Errorf("content mismatch: got %q", got)
	}
}

// TestAWSKMSRoundTrip requires AGE_RECIPIENTS and AGE_AWS_KMS_ENCRYPTED_KEY;
// skipped otherwise.
func TestAWSKMSRoundTrip(t *testing.T) {
	if (os.Getenv("AGE_RECIPIENTS") == "" && os.Getenv("AGE_RECIPIENTS_FILE") == "") || os.Getenv("AGE_AWS_KMS_ENCRYPTED_KEY") == "" {
		t.Skip("AGE_RECIPIENTS or AGE_RECIPIENTS_FILE, and AGE_AWS_KMS_ENCRYPTED_KEY must be set")
	}
	t.Setenv("AGE_KMS_PROVIDER", "aws")
	runKMSIntegrationTest(t)
}

// TestGCPKMSRoundTrip requires AGE_RECIPIENTS, AGE_GCP_KMS_ENCRYPTED_KEY, and
// GCP_KMS_KEY_NAME; skipped otherwise.
func TestGCPKMSRoundTrip(t *testing.T) {
	if (os.Getenv("AGE_RECIPIENTS") == "" && os.Getenv("AGE_RECIPIENTS_FILE") == "") || os.Getenv("AGE_GCP_KMS_ENCRYPTED_KEY") == "" || os.Getenv("GCP_KMS_KEY_NAME") == "" {
		t.Skip("AGE_RECIPIENTS or AGE_RECIPIENTS_FILE, and AGE_GCP_KMS_ENCRYPTED_KEY and GCP_KMS_KEY_NAME must be set")
	}
	t.Setenv("AGE_KMS_PROVIDER", "gcp")
	runKMSIntegrationTest(t)
}

// TestGetIdentityKMSDispatch verifies that when AGE_AWS_KMS_ENCRYPTED_KEY is set,
// GetIdentity uses the KMS path and not the key file fallback.
// AGE_SECRET_KEY_FILE is pointed at a nonexistent path so any fallback causes
// an immediate file-not-found error.
func TestGetIdentityKMSDispatch(t *testing.T) {
	dir := t.TempDir()

	keyFile := filepath.Join(dir, "age.key")
	_, err := agevault.GenerateIdentity(keyFile)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}

	t.Setenv("AGE_AWS_KMS_ENCRYPTED_KEY", base64.StdEncoding.EncodeToString([]byte("fake-kms-blob")))
	t.Setenv("AGE_GCP_KMS_ENCRYPTED_KEY", "")
	t.Setenv("AGE_KMS_PROVIDER", "")
	t.Setenv("AGE_SECRET_KEY_FILE", "/nonexistent/age.key")

	mock := &mockDecryptor{plaintext: keyData}
	v := agevault.NewVault()
	v.KMSDecryptor = mock

	if _, err := v.GetIdentity(); err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if !mock.called {
		t.Fatal("KMS decryptor was not called")
	}
}
