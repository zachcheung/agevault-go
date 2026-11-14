package agevault_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	agevault "github.com/zachcheung/agevault-go"
)

// fixedPassphrase returns a PassphrasePrompt that always answers pass and
// counts how many times it was asked.
func fixedPassphrase(pass string, calls *int) func(string) (string, error) {
	return func(string) (string, error) {
		if calls != nil {
			*calls++
		}
		return pass, nil
	}
}

func TestPassphraseProtectExistingKey(t *testing.T) {
	v, dir := setupTestEnv(t)
	keyFile := v.Config.SecretKeyFile
	wantPub, err := v.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	secret := writeFile(t, filepath.Join(dir, "secret.txt"), "hunter2\n")
	if err := v.Encrypt(false, secret); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	os.Remove(secret)

	v.PassphrasePrompt = fixedPassphrase("correct horse", nil)
	if err := v.SetKeyPassphrase(keyFile); err != nil {
		t.Fatalf("SetKeyPassphrase: %v", err)
	}

	onDisk := readFile(t, keyFile)
	if strings.Contains(onDisk, "AGE-SECRET-KEY-") {
		t.Fatalf("key file still contains the plaintext key:\n%s", onDisk)
	}
	if !strings.HasPrefix(onDisk, "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatalf("key file is not an armored age file:\n%s", onDisk)
	}
	if info, err := os.Stat(keyFile); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key file mode = %v (err %v), want 0600", info.Mode().Perm(), err)
	}

	// A fresh Vault unlocks the key once and reuses it for later files.
	calls := 0
	unlocked := &agevault.Vault{Config: v.Config, PassphrasePrompt: fixedPassphrase("correct horse", &calls)}
	gotPub, err := unlocked.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey with passphrase: %v", err)
	}
	if gotPub != wantPub {
		t.Fatalf("public key changed: got %s, want %s", gotPub, wantPub)
	}
	if err := unlocked.Decrypt(secret + ".age"); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got := readFile(t, secret); got != "hunter2\n" {
		t.Fatalf("decrypted content = %q", got)
	}
	if calls != 1 {
		t.Fatalf("passphrase prompted %d times, want 1", calls)
	}

	wrong := &agevault.Vault{Config: v.Config, PassphrasePrompt: fixedPassphrase("nope", nil)}
	if _, err := wrong.GetIdentity(); err == nil || !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Fatalf("wrong passphrase: got err %v, want incorrect passphrase", err)
	}
}

func TestPassphraseChange(t *testing.T) {
	v, _ := setupTestEnv(t)
	keyFile := v.Config.SecretKeyFile
	wantPub, _ := v.GetPublicKey()

	v.PassphrasePrompt = fixedPassphrase("old", nil)
	if err := v.SetKeyPassphrase(keyFile); err != nil {
		t.Fatalf("SetKeyPassphrase: %v", err)
	}

	// Changing: first answer is the current passphrase, then the new one twice.
	answers := []string{"old", "new", "new"}
	v.PassphrasePrompt = func(string) (string, error) {
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	if err := v.SetKeyPassphrase(keyFile); err != nil {
		t.Fatalf("change passphrase: %v", err)
	}

	old := &agevault.Vault{Config: v.Config, PassphrasePrompt: fixedPassphrase("old", nil)}
	if _, err := old.GetIdentity(); err == nil {
		t.Fatal("old passphrase still unlocks the key")
	}
	fresh := &agevault.Vault{Config: v.Config, PassphrasePrompt: fixedPassphrase("new", nil)}
	if gotPub, err := fresh.GetPublicKey(); err != nil || gotPub != wantPub {
		t.Fatalf("new passphrase: pub %s err %v, want %s", gotPub, err, wantPub)
	}
}

func TestPassphraseRejectsEmptyAndMismatch(t *testing.T) {
	v, _ := setupTestEnv(t)
	keyFile := v.Config.SecretKeyFile
	before := readFile(t, keyFile)

	v.PassphrasePrompt = fixedPassphrase("", nil)
	if err := v.SetKeyPassphrase(keyFile); err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("empty passphrase: got err %v", err)
	}

	answers := []string{"one", "two"}
	v.PassphrasePrompt = func(string) (string, error) {
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	if err := v.SetKeyPassphrase(keyFile); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched passphrase: got err %v", err)
	}

	if readFile(t, keyFile) != before {
		t.Fatal("key file was modified by a failed passphrase change")
	}
}

func TestInitWithPassphrase(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "sub", "age.key")
	v := &agevault.Vault{
		Config:           &agevault.Config{SecretKeyFile: keyFile, PubkeyExt: "pub"},
		PassphrasePrompt: fixedPassphrase("pw", nil),
	}
	if err := v.Init(true, true); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if strings.Contains(readFile(t, keyFile), "AGE-SECRET-KEY-") {
		t.Fatal("init --passphrase wrote a plaintext key")
	}
	pubFile := strings.TrimSpace(readFile(t, filepath.Join(dir, "sub", "age.pub")))
	if !strings.HasPrefix(pubFile, "age1pq1") {
		t.Fatalf("pub file = %q, want a hybrid public key", pubFile)
	}
	got, err := (&agevault.Vault{Config: v.Config, PassphrasePrompt: fixedPassphrase("pw", nil)}).GetPublicKey()
	if err != nil || got != pubFile {
		t.Fatalf("GetPublicKey = %s, %v; want %s", got, err, pubFile)
	}
	if err := v.Init(false, true); err == nil {
		t.Fatal("Init over an existing key file should fail")
	}
}

func TestKeygenProtectedToWriter(t *testing.T) {
	v := &agevault.Vault{Config: &agevault.Config{}, PassphrasePrompt: fixedPassphrase("pw", nil)}
	var buf bytes.Buffer
	pub, err := v.KeygenProtectedToWriter(false, &buf, "the new key")
	if err != nil {
		t.Fatalf("KeygenProtectedToWriter: %v", err)
	}
	if strings.Contains(buf.String(), "AGE-SECRET-KEY-") {
		t.Fatal("protected keygen wrote a plaintext key")
	}
	keyFile := writeFile(t, filepath.Join(t.TempDir(), "k"), buf.String())
	got, err := v.PublicKeyFromFile(keyFile)
	if err != nil || got != pub {
		t.Fatalf("PublicKeyFromFile = %s, %v; want %s", got, err, pub)
	}
}

// With no controlling terminal (and none injected), a protected key must fail
// with a clear error rather than hang or fall back to anything else.
func TestE2E_PassphraseKeyWithoutTerminal(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)

	secret := writeFile(t, filepath.Join(dir, "secret.txt"), "s3cret\n")
	if err := v.Encrypt(false, secret); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	v.PassphrasePrompt = fixedPassphrase("pw", nil)
	if err := v.SetKeyPassphrase(v.Config.SecretKeyFile); err != nil {
		t.Fatalf("SetKeyPassphrase: %v", err)
	}

	cmd := exec.Command(bin, "cat", secret+".age")
	cmd.Dir = dir
	cmd.Env = baseEnv("AGE_SECRET_KEY_FILE=" + v.Config.SecretKeyFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // detach from any controlling tty
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("cat succeeded without a passphrase; stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "passphrase-protected") || !strings.Contains(stderr.String(), "no terminal available") {
		t.Fatalf("stderr = %q, want a passphrase/no-terminal error", stderr.String())
	}
	if strings.Contains(stdout.String(), "s3cret") {
		t.Fatal("plaintext leaked to stdout")
	}
}
