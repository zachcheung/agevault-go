package agevault_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agevault "github.com/zachcheung/agevault-go"
)

// waitForSocket polls until path is dial-able as a Unix socket, or fails the test.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", path); err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("agent socket %s not ready", path)
}

func TestRunAgent(t *testing.T) {
	v, dir := setupTestEnv(t)

	envPlain := filepath.Join(dir, "app.env")
	writeFile(t, envPlain, "API_KEY=secret123\nDB_HOST=localhost\n")
	if err := v.Encrypt(false, envPlain); err != nil {
		t.Fatalf("Encrypt env: %v", err)
	}

	certPlain := filepath.Join(dir, "cert.pem")
	writeFile(t, certPlain, "cert-bytes")
	if err := v.Encrypt(false, certPlain); err != nil {
		t.Fatalf("Encrypt cert: %v", err)
	}

	socketPath := filepath.Join(dir, "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- v.RunAgent(ctx, socketPath, []string{envPlain + ".age"}, []string{certPlain + ".age"})
	}()

	waitForSocket(t, socketPath)

	bundle, err := agevault.DialAgentBundle(socketPath)
	if err != nil {
		t.Fatalf("DialAgentBundle: %v", err)
	}

	assertEqual(t, "env", []string{"API_KEY=secret123", "DB_HOST=localhost"}, bundle.Env)
	if got := string(bundle.Files["cert.pem"]); got != "cert-bytes" {
		t.Errorf("Files[cert.pem] = %q, want %q", got, "cert-bytes")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunAgent returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunAgent did not shut down after context cancellation")
	}

	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Errorf("socket file %s still exists after shutdown", socketPath)
	}
}

func TestRunAgentDuplicateDecryptBasename(t *testing.T) {
	v, dir := setupTestEnv(t)

	aDir := filepath.Join(dir, "a")
	bDir := filepath.Join(dir, "b")
	if err := os.MkdirAll(aDir, 0755); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}
	if err := os.MkdirAll(bDir, 0755); err != nil {
		t.Fatalf("mkdir b: %v", err)
	}

	certA := writeFile(t, filepath.Join(aDir, "cert.pem"), "cert-a")
	certB := writeFile(t, filepath.Join(bDir, "cert.pem"), "cert-b")
	if err := v.Encrypt(false, certA, certB); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	socketPath := filepath.Join(dir, "agent.sock")
	err := v.RunAgent(context.Background(), socketPath, nil, []string{certA + ".age", certB + ".age"})
	if err == nil {
		t.Fatal("expected error for duplicate decrypt file basename, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate decrypt file basename") {
		t.Errorf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(socketPath); !os.IsNotExist(statErr) {
		t.Errorf("socket file %s should not have been created", socketPath)
	}
}

func TestApplyAgentBundle(t *testing.T) {
	dir := t.TempDir()
	bundle := &agevault.AgentBundle{
		Env: []string{"FOO=bar"},
		Files: map[string][]byte{
			"cert.pem": []byte("cert-bytes"),
		},
	}

	environ, err := agevault.ApplyAgentBundle(bundle, []string{"EXISTING=1", "FOO=old"}, dir)
	if err != nil {
		t.Fatalf("ApplyAgentBundle: %v", err)
	}

	assertEqual(t, "environ", []string{"EXISTING=1", "FOO=bar"}, environ)

	got := readFile(t, filepath.Join(dir, "cert.pem"))
	if got != "cert-bytes" {
		t.Errorf("cert.pem content = %q, want %q", got, "cert-bytes")
	}
}
