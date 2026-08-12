// End-to-end tests that build the real agevault binary and drive it as a
// subprocess, mirroring the command coverage of the shell version's
// agevault_test.sh. Unlike that script, every test case gets its own
// t.TempDir() and its own explicit subprocess environment (never the parent
// process's env), so commands in one case can never affect another — cases
// are safe to run with t.Parallel().
package agevault_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	agevault "github.com/zachcheung/agevault-go"
)

var (
	e2eBinOnce sync.Once
	e2eBinPath string
	e2eBinErr  error
)

// buildAgevaultBinary builds the real agevault CLI once and returns its path.
// The binary is immutable once built, so sharing it across parallel subtests
// is safe — only test *state* (temp dirs, env vars) needs isolation.
func buildAgevaultBinary(t *testing.T) string {
	t.Helper()
	e2eBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "agevault-e2e-bin-*")
		if err != nil {
			e2eBinErr = err
			return
		}
		e2eBinPath = filepath.Join(dir, "agevault")
		cmd := exec.Command("go", "build", "-o", e2eBinPath, "./cmd/agevault")
		if out, err := cmd.CombinedOutput(); err != nil {
			e2eBinErr = fmt.Errorf("build agevault binary: %w\n%s", err, out)
		}
	})
	if e2eBinErr != nil {
		t.Fatalf("%v", e2eBinErr)
	}
	return e2eBinPath
}

// baseEnv returns a minimal subprocess environment (just PATH, so 'sh',
// 'git', etc. resolve) plus any extra "KEY=VALUE" entries.
func baseEnv(extra ...string) []string {
	return append([]string{"PATH=" + os.Getenv("PATH")}, extra...)
}

// runCLI runs the agevault binary as a subprocess with an explicit
// environment and working directory, returning its stdout/stderr.
func runCLI(t *testing.T, bin, dir string, env []string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func TestE2E_EncryptDecrypt_AgeRecipients(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	dir := t.TempDir()

	keyFile1 := filepath.Join(dir, "key1")
	id1, err := agevault.GenerateIdentity(keyFile1)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	keyFile2 := filepath.Join(dir, "key2")
	id2, err := agevault.GenerateIdentity(keyFile2)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	encFile := plain + ".age"

	recipients := id1.Recipient().String() + "," + id2.Recipient().String()
	if _, stderr, err := runCLI(t, bin, dir, baseEnv("AGE_RECIPIENTS="+recipients), "encrypt", plain); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, stderr)
	}
	os.Remove(plain)

	for _, keyFile := range []string{keyFile1, keyFile2} {
		if _, stderr, err := runCLI(t, bin, dir, baseEnv("AGE_SECRET_KEY_FILE="+keyFile), "decrypt", encFile); err != nil {
			t.Fatalf("decrypt with %s: %v\n%s", keyFile, err, stderr)
		}
		if got := readFile(t, plain); got != "hello world\n" {
			t.Errorf("decrypt with %s: content = %q", keyFile, got)
		}
		os.Remove(plain)
	}
}

func TestE2E_EncryptSelf_KeyFile(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	dir := t.TempDir()

	keyFile := filepath.Join(dir, "age.key")
	if _, err := agevault.GenerateIdentity(keyFile); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	encFile := plain + ".age"
	env := baseEnv("AGE_SECRET_KEY_FILE=" + keyFile)

	if _, stderr, err := runCLI(t, bin, dir, env, "encrypt", "--self", plain); err != nil {
		t.Fatalf("encrypt --self: %v\n%s", err, stderr)
	}
	os.Remove(plain)

	if _, stderr, err := runCLI(t, bin, dir, env, "decrypt", encFile); err != nil {
		t.Fatalf("decrypt: %v\n%s", err, stderr)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content = %q", got)
	}
}

func TestE2E_EncryptSelf_InlineKey(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	dir := t.TempDir()

	keyFile := filepath.Join(dir, "age.key")
	id, err := agevault.GenerateIdentity(keyFile)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	encFile := plain + ".age"
	env := baseEnv("AGE_SECRET_KEY=" + id.String())

	if _, stderr, err := runCLI(t, bin, dir, env, "encrypt", "--self", plain); err != nil {
		t.Fatalf("encrypt --self: %v\n%s", err, stderr)
	}
	os.Remove(plain)

	if _, stderr, err := runCLI(t, bin, dir, env, "decrypt", encFile); err != nil {
		t.Fatalf("decrypt: %v\n%s", err, stderr)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content = %q", got)
	}
}

// TestE2E_Decrypt_KeyPrecedence verifies AGE_SECRET_KEY takes precedence over
// AGE_SECRET_KEY_FILE even when the latter points nowhere.
func TestE2E_Decrypt_KeyPrecedence(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	dir := t.TempDir()

	keyFile := filepath.Join(dir, "age.key")
	id, err := agevault.GenerateIdentity(keyFile)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	recipientsFile := filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(recipientsFile, []byte(id.Recipient().String()+"\n"), 0644); err != nil {
		t.Fatalf("write recipients: %v", err)
	}

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	encFile := plain + ".age"

	v := &agevault.Vault{Config: &agevault.Config{RecipientsFile: recipientsFile, PubkeyExt: "pub"}}
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	os.Remove(plain)

	env := baseEnv(
		"AGE_SECRET_KEY="+id.String(),
		"AGE_SECRET_KEY_FILE=/nonexistent/does-not-exist",
	)
	if _, stderr, err := runCLI(t, bin, dir, env, "decrypt", encFile); err != nil {
		t.Fatalf("decrypt should have used AGE_SECRET_KEY, not AGE_SECRET_KEY_FILE: %v\n%s", err, stderr)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content = %q", got)
	}
}

func TestE2E_Cat(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	encFile := plain + ".age"

	env := baseEnv("AGE_SECRET_KEY_FILE=" + v.Config.SecretKeyFile)
	stdout, stderr, err := runCLI(t, bin, dir, env, "cat", encFile)
	if err != nil {
		t.Fatalf("cat: %v\n%s", err, stderr)
	}
	if stdout != "hello world\n" {
		t.Errorf("cat stdout = %q", stdout)
	}
}

func TestE2E_Reencrypt(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	os.Remove(plain)
	encFile := plain + ".age"

	env := baseEnv(
		"AGE_SECRET_KEY_FILE="+v.Config.SecretKeyFile,
		"AGE_RECIPIENTS_FILE="+v.Config.RecipientsFile,
	)
	if _, stderr, err := runCLI(t, bin, dir, env, "reencrypt", encFile); err != nil {
		t.Fatalf("reencrypt: %v\n%s", err, stderr)
	}

	if err := v.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt after reencrypt: %v", err)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content after reencrypt = %q", got)
	}
}

func TestE2E_ReencryptAll(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	os.Remove(plain)
	encFile := plain + ".age"

	for _, args := range [][]string{
		{"init"},
		{"add", "."},
		{"-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	env := baseEnv(
		"AGE_SECRET_KEY_FILE="+v.Config.SecretKeyFile,
		"AGE_RECIPIENTS_FILE="+v.Config.RecipientsFile,
	)
	if _, stderr, err := runCLI(t, bin, dir, env, "reencrypt", "--all"); err != nil {
		t.Fatalf("reencrypt --all: %v\n%s", err, stderr)
	}

	if err := v.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt after reencrypt --all: %v", err)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content after reencrypt --all = %q", got)
	}
}

func TestE2E_Rotate(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	os.Remove(plain)
	encFile := plain + ".age"

	newKeyFile := filepath.Join(dir, "new.key")
	env := baseEnv(
		"AGE_SECRET_KEY_FILE="+v.Config.SecretKeyFile,
		"AGE_RECIPIENTS_FILE="+v.Config.RecipientsFile,
	)
	if _, stderr, err := runCLI(t, bin, dir, env, "rotate", "--new-key", newKeyFile, encFile); err != nil {
		t.Fatalf("rotate: %v\n%s", err, stderr)
	}

	rotated := &agevault.Vault{Config: &agevault.Config{SecretKeyFile: newKeyFile, RecipientsFile: v.Config.RecipientsFile, PubkeyExt: "pub"}}
	if err := rotated.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt with rotated key: %v", err)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content after rotate = %q", got)
	}

	// The old key must no longer be able to decrypt.
	os.Remove(plain)
	if err := v.Decrypt(encFile); err == nil {
		t.Error("old key should no longer decrypt after rotate")
	}
}

func TestE2E_RotateKeepOldKey(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	os.Remove(plain)
	encFile := plain + ".age"

	newKeyFile := filepath.Join(dir, "new.key")
	env := baseEnv(
		"AGE_SECRET_KEY_FILE="+v.Config.SecretKeyFile,
		"AGE_RECIPIENTS_FILE="+v.Config.RecipientsFile,
	)
	if _, stderr, err := runCLI(t, bin, dir, env, "rotate", "--new-key", newKeyFile, "--keep-old-key", encFile); err != nil {
		t.Fatalf("rotate --keep-old-key: %v\n%s", err, stderr)
	}

	// Both old and new keys must decrypt.
	if err := v.Decrypt(encFile); err != nil {
		t.Fatalf("old key should still decrypt: %v", err)
	}
	os.Remove(plain)
	rotated := &agevault.Vault{Config: &agevault.Config{SecretKeyFile: newKeyFile, RecipientsFile: v.Config.RecipientsFile, PubkeyExt: "pub"}}
	if err := rotated.Decrypt(encFile); err != nil {
		t.Fatalf("new key should decrypt: %v", err)
	}
	os.Remove(plain)

	// Running --keep-old-key again must not duplicate the new recipient.
	before, err := os.ReadFile(v.Config.RecipientsFile)
	if err != nil {
		t.Fatalf("read recipients: %v", err)
	}
	if _, stderr, err := runCLI(t, bin, dir, env, "rotate", "--new-key", newKeyFile, "--keep-old-key", encFile); err != nil {
		t.Fatalf("second rotate --keep-old-key: %v\n%s", err, stderr)
	}
	after, err := os.ReadFile(v.Config.RecipientsFile)
	if err != nil {
		t.Fatalf("read recipients: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("rotate --keep-old-key duplicated a recipient:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestE2E_Edit(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	plain := filepath.Join(dir, "note.txt")
	writeFile(t, plain, "hello world\n")
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	os.Remove(plain)
	encFile := plain + ".age"

	script := filepath.Join(dir, "editor.sh")
	writeFile(t, script, "#!/bin/sh\nsed -i 's/world/universe/' \"$1\"\n")
	if err := os.Chmod(script, 0755); err != nil {
		t.Fatalf("chmod editor script: %v", err)
	}

	env := baseEnv(
		"AGE_SECRET_KEY_FILE="+v.Config.SecretKeyFile,
		"AGE_RECIPIENTS_FILE="+v.Config.RecipientsFile,
		"EDITOR="+script,
	)
	if _, stderr, err := runCLI(t, bin, dir, env, "edit", encFile); err != nil {
		t.Fatalf("edit: %v\n%s", err, stderr)
	}

	stdout, stderr, err := runCLI(t, bin, dir, env, "cat", encFile)
	if err != nil {
		t.Fatalf("cat after edit: %v\n%s", err, stderr)
	}
	if stdout != "hello universe\n" {
		t.Errorf("content after edit = %q", stdout)
	}
}

func TestE2E_Run(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	envPlain := filepath.Join(dir, "app.env")
	writeFile(t, envPlain, "TEST_VAR=42\n")
	if err := v.Encrypt(false, envPlain); err != nil {
		t.Fatalf("Encrypt env fixture: %v", err)
	}
	os.Remove(envPlain)

	dataPlain := filepath.Join(dir, "data.txt")
	writeFile(t, dataPlain, "sensitive-data\n")
	if err := v.Encrypt(false, dataPlain); err != nil {
		t.Fatalf("Encrypt data fixture: %v", err)
	}
	os.Remove(dataPlain)

	env := baseEnv("AGE_SECRET_KEY_FILE=" + v.Config.SecretKeyFile)

	// Backwards-compat bare positional env file.
	stdout, stderr, err := runCLI(t, bin, dir, env, "run", envPlain+".age", "--", "sh", "-c", "echo $TEST_VAR")
	if err != nil {
		t.Fatalf("run (positional env): %v\n%s", err, stderr)
	}
	if stdout != "42\n" {
		t.Errorf("run (positional env) stdout = %q", stdout)
	}

	// --env and --decrypt combined.
	stdout, stderr, err = runCLI(t, bin, dir, env, "run", "--env", envPlain+".age", "--decrypt", dataPlain+".age",
		"--", "sh", "-c", fmt.Sprintf("test -f %q && echo $TEST_VAR", dataPlain))
	if err != nil {
		t.Fatalf("run --env --decrypt: %v\n%s", err, stderr)
	}
	if stdout != "42\n" {
		t.Errorf("run --env --decrypt stdout = %q", stdout)
	}
	if got := readFile(t, dataPlain); got != "sensitive-data\n" {
		t.Errorf("run --decrypt did not write file content = %q", got)
	}
}

func TestE2E_KeyAddReadd(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	dir := t.TempDir()

	keyFile := filepath.Join(dir, "age.key")
	id, err := agevault.GenerateIdentity(keyFile)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	keySrv := filepath.Join(dir, "keysrv")
	if err := os.MkdirAll(keySrv, 0755); err != nil {
		t.Fatalf("mkdir keysrv: %v", err)
	}
	pubLine := id.Recipient().String() + "\n"
	if err := os.WriteFile(filepath.Join(keySrv, "testuser.pub"), []byte(pubLine), 0644); err != nil {
		t.Fatalf("write testuser.pub: %v", err)
	}

	recipientsFile := filepath.Join(dir, "recipients.txt")
	env := baseEnv(
		"AGE_KEY_SERVER=file://"+keySrv,
		"AGE_RECIPIENTS_FILE="+recipientsFile,
	)

	if _, stderr, err := runCLI(t, bin, dir, env, "key-add", "testuser"); err != nil {
		t.Fatalf("key-add: %v\n%s", err, stderr)
	}
	if got := readFile(t, recipientsFile); got != pubLine {
		t.Errorf("recipients after key-add = %q, want %q", got, pubLine)
	}

	// Corrupt the recipients file, then key-readd must reset it.
	if err := os.WriteFile(recipientsFile, []byte("garbage\n"+pubLine), 0644); err != nil {
		t.Fatalf("corrupt recipients: %v", err)
	}
	if _, stderr, err := runCLI(t, bin, dir, env, "key-readd", "testuser"); err != nil {
		t.Fatalf("key-readd: %v\n%s", err, stderr)
	}
	if got := readFile(t, recipientsFile); got != pubLine {
		t.Errorf("recipients after key-readd = %q, want %q", got, pubLine)
	}
}

func TestE2E_Agent(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	envPlain := filepath.Join(dir, "app.env")
	writeFile(t, envPlain, "API_KEY=secret123\n")
	if err := v.Encrypt(false, envPlain); err != nil {
		t.Fatalf("Encrypt env fixture: %v", err)
	}
	os.Remove(envPlain)

	certPlain := filepath.Join(dir, "cert.pem")
	writeFile(t, certPlain, "cert-bytes")
	if err := v.Encrypt(false, certPlain); err != nil {
		t.Fatalf("Encrypt cert fixture: %v", err)
	}
	os.Remove(certPlain)

	socketPath := filepath.Join(dir, "agent.sock")
	agentEnv := baseEnv("AGE_SECRET_KEY_FILE=" + v.Config.SecretKeyFile)
	agentCmd := exec.Command(bin, "agent", "--socket", socketPath, "--env", envPlain+".age", "--decrypt", certPlain+".age")
	agentCmd.Env = agentEnv
	agentCmd.Dir = dir
	var agentStderr bytes.Buffer
	agentCmd.Stderr = &agentStderr
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	t.Cleanup(func() {
		agentCmd.Process.Kill()
		agentCmd.Wait()
	})

	waitForSocket(t, socketPath)

	clientDir := filepath.Join(dir, "client")
	if err := os.MkdirAll(clientDir, 0755); err != nil {
		t.Fatalf("mkdir client dir: %v", err)
	}
	stdout, stderr, err := runCLI(t, bin, clientDir, baseEnv("AGE_AGENT_SOCKET="+socketPath),
		"agent-run", "--", "sh", "-c", "echo API_KEY=$API_KEY; cat cert.pem")
	if err != nil {
		t.Fatalf("agent-run: %v\n%s", err, stderr)
	}
	if stdout != "API_KEY=secret123\ncert-bytes" {
		t.Errorf("agent-run stdout = %q", stdout)
	}

	if err := agentCmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal agent: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- agentCmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("agent exited with error: %v\n%s", err, agentStderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not shut down after SIGTERM")
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Errorf("socket file still exists after agent shutdown")
	}
}
