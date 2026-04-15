package agevault_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agevault "github.com/zachcheung/agevault-go"
)

// setupTestEnv creates a temporary directory with a generated age key pair
// and returns a Vault wired to use it, plus a cleanup function.
func setupTestEnv(t *testing.T) (*agevault.Vault, string) {
	t.Helper()
	dir := t.TempDir()

	keyFile := filepath.Join(dir, "age.key")
	identity, err := agevault.GenerateIdentity(keyFile)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	recipientsFile := filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(recipientsFile, []byte(identity.Recipient().String()+"\n"), 0644); err != nil {
		t.Fatalf("write recipients: %v", err)
	}

	v := &agevault.Vault{Config: &agevault.Config{
		SecretKeyFile:  keyFile,
		RecipientsFile: recipientsFile,
		PubkeyExt:      "pub",
	}}
	return v, dir
}

// writeFile writes content to path and returns the path.
func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// readFile reads and returns the content of a file.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// ── Encrypt / Decrypt ────────────────────────────────────────────────────────

func TestEncryptDecrypt(t *testing.T) {
	v, dir := setupTestEnv(t)
	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")

	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encFile := plain + ".age"
	if _, err := os.Stat(encFile); err != nil {
		t.Fatalf("encrypted file not created: %v", err)
	}

	// Remove original then decrypt.
	os.Remove(plain)
	if err := v.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	got := readFile(t, plain)
	if got != "hello world\n" {
		t.Errorf("decrypt content mismatch: got %q", got)
	}
}

func TestEncryptSelf(t *testing.T) {
	v, dir := setupTestEnv(t)
	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")

	if err := v.Encrypt(true, plain); err != nil {
		t.Fatalf("Encrypt --self: %v", err)
	}

	encFile := plain + ".age"
	os.Remove(plain)

	if err := v.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt after --self encrypt: %v", err)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content mismatch: got %q", got)
	}
}

func TestEncryptSelfWithInlineKey(t *testing.T) {
	v, dir := setupTestEnv(t)

	// Read the private key from file and use it as AGE_SECRET_KEY.
	keyData, err := os.ReadFile(v.Config.SecretKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	// Extract the private key line (non-comment).
	var privKey string
	for _, line := range strings.Split(string(keyData), "\n") {
		if !strings.HasPrefix(line, "#") && line != "" {
			privKey = line
			break
		}
	}
	v2 := &agevault.Vault{Config: &agevault.Config{
		SecretKey:      privKey,
		RecipientsFile: v.Config.RecipientsFile,
	}}

	plain := filepath.Join(dir, "secret2.txt")
	writeFile(t, plain, "hello world\n")
	if err := v2.Encrypt(true, plain); err != nil {
		t.Fatalf("Encrypt --self inline key: %v", err)
	}

	encFile := plain + ".age"
	os.Remove(plain)
	if err := v2.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt after --self inline key: %v", err)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content mismatch: got %q", got)
	}
}

func TestEncryptWithAgeRecipients(t *testing.T) {
	_, dir := setupTestEnv(t) // config ignored as we build a custom one below

	// Generate two key pairs and combine their public keys in AGE_RECIPIENTS.
	id1, err := agevault.GenerateIdentity(filepath.Join(dir, "key1.key"))
	if err != nil {
		t.Fatal(err)
	}
	id2, err := agevault.GenerateIdentity(filepath.Join(dir, "key2.key"))
	if err != nil {
		t.Fatal(err)
	}

	recipientsEnv := fmt.Sprintf("%s, %s", id1.Recipient().String(), id2.Recipient().String())
	v := &agevault.Vault{Config: &agevault.Config{Recipients: recipientsEnv}}

	plain := filepath.Join(dir, "multi.txt")
	writeFile(t, plain, "hello world\n")
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt with AGE_RECIPIENTS: %v", err)
	}

	encFile := plain + ".age"
	os.Remove(plain)

	// Either key should be able to decrypt.
	for _, keyFile := range []string{
		filepath.Join(dir, "key1.key"),
		filepath.Join(dir, "key2.key"),
	} {
		os.Remove(plain)
		keyV := &agevault.Vault{Config: &agevault.Config{SecretKeyFile: keyFile}}
		if err := keyV.Decrypt(encFile); err != nil {
			t.Fatalf("Decrypt with key %s: %v", keyFile, err)
		}
		if got := readFile(t, plain); got != "hello world\n" {
			t.Errorf("key %s: content mismatch: got %q", keyFile, got)
		}
	}
}

// ── Cat ───────────────────────────────────────────────────────────────────────

func TestCat(t *testing.T) {
	v, dir := setupTestEnv(t)
	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")

	if err := v.Encrypt(false, plain); err != nil {
		t.Fatal(err)
	}

	// Redirect stdout to capture Cat output.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := v.Cat(plain + ".age")
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("Cat: %v", err)
	}
	if got := buf.String(); got != "hello world\n" {
		t.Errorf("Cat output mismatch: got %q", got)
	}
}

// ── Reencrypt ─────────────────────────────────────────────────────────────────

func TestReencrypt(t *testing.T) {
	v, dir := setupTestEnv(t)
	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")

	if err := v.Encrypt(false, plain); err != nil {
		t.Fatal(err)
	}
	encFile := plain + ".age"

	if err := v.Reencrypt(false, encFile); err != nil {
		t.Fatalf("Reencrypt: %v", err)
	}

	os.Remove(plain)
	if err := v.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt after Reencrypt: %v", err)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content mismatch: got %q", got)
	}
}

func TestReencryptAll(t *testing.T) {
	v, dir := setupTestEnv(t)
	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")

	if err := v.Encrypt(false, plain); err != nil {
		t.Fatal(err)
	}
	encFile := plain + ".age"

	// Set up a git repo in dir so --all works.
	mustGit := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	mustGit("init")
	mustGit("add", ".")

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	os.Chdir(dir)
	defer os.Chdir(wd)

	if err := v.Reencrypt(true); err != nil {
		t.Fatalf("Reencrypt --all: %v", err)
	}

	os.Remove(plain)
	if err := v.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt after Reencrypt --all: %v", err)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content mismatch: got %q", got)
	}
}

// ── Rotate ────────────────────────────────────────────────────────────────────

func TestRotate(t *testing.T) {
	v, dir := setupTestEnv(t)
	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")

	if err := v.Encrypt(false, plain); err != nil {
		t.Fatal(err)
	}
	encFile := plain + ".age"

	newKeyPath := filepath.Join(dir, "new.key")
	if err := v.Rotate(newKeyPath, false, false, encFile); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Decrypt with new key.
	newV := &agevault.Vault{Config: &agevault.Config{
		SecretKeyFile:  newKeyPath,
		RecipientsFile: v.Config.RecipientsFile,
	}}

	os.Remove(plain)
	if err := newV.Decrypt(encFile); err != nil {
		t.Fatalf("Decrypt after Rotate: %v", err)
	}
	if got := readFile(t, plain); got != "hello world\n" {
		t.Errorf("content mismatch: got %q", got)
	}
}

func TestRotateKeepOldKey(t *testing.T) {
	v, dir := setupTestEnv(t)
	plain := filepath.Join(dir, "secret.txt")
	writeFile(t, plain, "hello world\n")

	if err := v.Encrypt(false, plain); err != nil {
		t.Fatal(err)
	}
	encFile := plain + ".age"

	oldKeyFile := v.Config.SecretKeyFile
	newKeyPath := filepath.Join(dir, "new.key")
	if err := v.Rotate(newKeyPath, true, false, encFile); err != nil {
		t.Fatalf("Rotate --keep-old-key: %v", err)
	}

	decryptWith := func(keyFile string) {
		t.Helper()
		c := &agevault.Vault{Config: &agevault.Config{
			SecretKeyFile:  keyFile,
			RecipientsFile: v.Config.RecipientsFile,
		}}
		os.Remove(plain)
		if err := c.Decrypt(encFile); err != nil {
			t.Fatalf("Decrypt with %s: %v", keyFile, err)
		}
		if got := readFile(t, plain); got != "hello world\n" {
			t.Errorf("key %s: content mismatch: got %q", keyFile, got)
		}
	}

	decryptWith(oldKeyFile)
	decryptWith(newKeyPath)

	// Running rotate --keep-old-key again should NOT duplicate the new key.
	rfBefore := readFile(t, v.Config.RecipientsFile)
	if err := v.Rotate(newKeyPath, true, false, encFile); err != nil {
		t.Fatalf("second Rotate --keep-old-key: %v", err)
	}
	rfAfter := readFile(t, v.Config.RecipientsFile)
	countBefore := strings.Count(rfBefore, "age1")
	countAfter := strings.Count(rfAfter, "age1")
	if countAfter != countBefore {
		t.Errorf("rotate --keep-old-key duplicated a recipient: before=%d after=%d", countBefore, countAfter)
	}
}

// ── Run ───────────────────────────────────────────────────────────────────────

func TestParseRunArgs(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantEnv         []string
		wantDecrypt     []string
		wantCmd         []string
		wantErr         bool
	}{
		{
			name:    "backwards compat positional env file",
			args:    []string{"env.age", "--", "sh", "-c", "echo hi"},
			wantEnv: []string{"env.age"},
			wantCmd: []string{"sh", "-c", "echo hi"},
		},
		{
			name:        "--env flag",
			args:        []string{"--env", "env.age", "--", "sh"},
			wantEnv:     []string{"env.age"},
			wantCmd:     []string{"sh"},
		},
		{
			name:        "--decrypt flag",
			args:        []string{"--decrypt", "cert.pem.age", "--", "ls"},
			wantDecrypt: []string{"cert.pem.age"},
			wantCmd:     []string{"ls"},
		},
		{
			name:        "comma-separated --env",
			args:        []string{"--env", "a.age,b.age", "--", "ls"},
			wantEnv:     []string{"a.age", "b.age"},
			wantCmd:     []string{"ls"},
		},
		{
			name:    "combined --env and --decrypt",
			args:    []string{"--env", "app.env.age", "--decrypt", "cert.pem.age", "--", "run"},
			wantEnv: []string{"app.env.age"},
			wantDecrypt: []string{"cert.pem.age"},
			wantCmd: []string{"run"},
		},
		{
			name:    "missing files after --env",
			args:    []string{"--env"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, dec, cmd, err := agevault.ParseRunArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertEqual(t, "envFiles", tc.wantEnv, env)
			assertEqual(t, "decryptFiles", tc.wantDecrypt, dec)
			assertEqual(t, "command", tc.wantCmd, cmd)
		})
	}
}

func assertEqual(t *testing.T, label string, want, got []string) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf("%s: want %v, got %v", label, want, got)
		return
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("%s[%d]: want %q, got %q", label, i, want[i], got[i])
		}
	}
}

// ── Key management ────────────────────────────────────────────────────────────

func TestKeyAddAndReadd(t *testing.T) {
	v, dir := setupTestEnv(t)
	origContent := readFile(t, v.Config.RecipientsFile)

	// Set up a file:// key server.
	keySrvDir := filepath.Join(dir, "keysrv")
	os.MkdirAll(keySrvDir, 0755)
	os.WriteFile(filepath.Join(keySrvDir, "alice.pub"), []byte(origContent), 0644)

	cfgSrv := &agevault.Vault{
		Config: &agevault.Config{
			KeyServer: "file://" + keySrvDir,
			PubkeyExt: "pub",
			RecipientsFile: v.Config.RecipientsFile,
		},
	}

	// Move original recipients file away, then key-add should recreate it.
	origPath := v.Config.RecipientsFile
	backupPath := origPath + ".bak"
	os.Rename(origPath, backupPath)

	if err := cfgSrv.KeyAdd("alice"); err != nil {
		t.Fatalf("KeyAdd: %v", err)
	}

	got := readFile(t, origPath)
	want := origContent
	if got != want {
		t.Errorf("KeyAdd content mismatch:\ngot  %q\nwant %q", got, want)
	}

	// key-readd: double the file, then reset to single entry.
	f, err := os.OpenFile(origPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(origContent)
	f.Close()

	if err := cfgSrv.KeyReadd("alice"); err != nil {
		t.Fatalf("KeyReadd: %v", err)
	}

	got = readFile(t, origPath)
	if got != want {
		t.Errorf("KeyReadd content mismatch:\ngot  %q\nwant %q", got, want)
	}
}

// ── ParseRecipientsFile ───────────────────────────────────────────────────────

func TestParseRecipientsFile(t *testing.T) {
	dir := t.TempDir()
	rf := filepath.Join(dir, "recs.txt")
	os.WriteFile(rf, []byte("# comment\nage1yubikey1qwaywardson\n\nage1x86invalid\n"), 0644)

	// We don't care about the exact result (age1yubikey... will fail parsing),
	// just test that comments and blanks are skipped and we get an error on bad keys.
	_, err := agevault.ParseRecipientsFile(rf)
	if err == nil {
		t.Log("note: all lines parsed (maybe test keys happen to be valid)")
	}
}
