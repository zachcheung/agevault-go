package agevault_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	agevault "github.com/zachcheung/agevault-go"
	"github.com/zachcheung/agevault-go/keyagent"
)

// startKeyAgent runs an empty key agent on a fresh socket for the duration of
// the test and returns the socket path.
func startKeyAgent(t *testing.T) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "key-agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- new(keyagent.Agent).Serve(ctx, socket) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("KeyAgent.Serve: %v", err)
		}
	})
	waitForKeyAgent(t, socket)
	return socket
}

func waitForKeyAgent(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := keyagent.List(socket); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("key agent did not come up on %s", socket)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// noPrompt fails the test if a passphrase is ever asked for.
func noPrompt(t *testing.T) func(string) (string, error) {
	return func(prompt string) (string, error) {
		t.Errorf("unexpected passphrase prompt: %q", prompt)
		return "", errors.New("no prompt expected")
	}
}

func TestKeyAgentDecryptWithoutKeyFile(t *testing.T) {
	v, dir := setupTestEnv(t)
	wantPub, _ := v.GetPublicKey()

	secret := writeFile(t, filepath.Join(dir, "secret.txt"), "via agent\n")
	if err := v.Encrypt(false, secret); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	os.Remove(secret)

	// Protect the key, add it to the agent (one passphrase entry) ...
	v.PassphrasePrompt = fixedPassphrase("pw", nil)
	if err := v.SetKeyPassphrase(v.Config.SecretKeyFile); err != nil {
		t.Fatalf("SetKeyPassphrase: %v", err)
	}
	socket := startKeyAgent(t)
	added, err := v.AddKeyToAgent(socket, v.Config.SecretKeyFile, 0)
	if err != nil {
		t.Fatalf("AddKeyToAgent: %v", err)
	}
	if len(added) != 1 || added[0] != wantPub {
		t.Fatalf("added = %v, want [%s]", added, wantPub)
	}

	// ... then a client with the agent socket never prompts again.
	client := &agevault.Vault{
		Config: &agevault.Config{
			SecretKeyFile:  v.Config.SecretKeyFile,
			RecipientsFile: v.Config.RecipientsFile,
			KeyAgentSocket: socket,
		},
		PassphrasePrompt: noPrompt(t),
	}
	if err := client.Decrypt(secret + ".age"); err != nil {
		t.Fatalf("Decrypt via agent: %v", err)
	}
	if got := readFile(t, secret); got != "via agent\n" {
		t.Fatalf("decrypted content = %q", got)
	}
	if pub, err := client.GetPublicKey(); err != nil || pub != wantPub {
		t.Fatalf("GetPublicKey via agent = %s, %v; want %s", pub, err, wantPub)
	}

	// --self needs only the public key, which the agent provides.
	self := writeFile(t, filepath.Join(dir, "self.txt"), "self\n")
	if err := client.Encrypt(true, self); err != nil {
		t.Fatalf("Encrypt --self via agent: %v", err)
	}
	os.Remove(self)
	if err := client.Decrypt(self + ".age"); err != nil {
		t.Fatalf("Decrypt self via agent: %v", err)
	}

	// Reencrypt exercises decrypt + recipients through the agent identity.
	if err := client.Reencrypt(false, secret+".age"); err != nil {
		t.Fatalf("Reencrypt via agent: %v", err)
	}
}

func TestKeyAgentHybridKey(t *testing.T) {
	v, dir := setupHybridTestEnv(t)
	secret := writeFile(t, filepath.Join(dir, "secret.txt"), "pq\n")
	if err := v.Encrypt(false, secret); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	os.Remove(secret)

	socket := startKeyAgent(t)
	if _, err := v.AddKeyToAgent(socket, v.Config.SecretKeyFile, 0); err != nil {
		t.Fatalf("AddKeyToAgent: %v", err)
	}
	client := &agevault.Vault{Config: &agevault.Config{
		SecretKeyFile:  v.Config.SecretKeyFile,
		KeyAgentSocket: socket,
	}}
	pub, err := client.GetPublicKey()
	if err != nil || !strings.HasPrefix(pub, "age1pq1") {
		t.Fatalf("GetPublicKey = %s, %v; want a hybrid key", pub, err)
	}
	if err := client.Decrypt(secret + ".age"); err != nil {
		t.Fatalf("Decrypt hybrid via agent: %v", err)
	}
	if got := readFile(t, secret); got != "pq\n" {
		t.Fatalf("decrypted content = %q", got)
	}
}

func TestKeyAgentListClearAndFallback(t *testing.T) {
	v, dir := setupTestEnv(t)
	other, _ := setupTestEnv(t)
	socket := startKeyAgent(t)

	if keys, err := keyagent.List(socket); err != nil || len(keys) != 0 {
		t.Fatalf("fresh agent: keys %v, err %v", keys, err)
	}

	secret := writeFile(t, filepath.Join(dir, "secret.txt"), "x\n")
	if err := v.Encrypt(false, secret); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// An agent holding only an unrelated key cannot decrypt the file ...
	if _, err := other.AddKeyToAgent(socket, other.Config.SecretKeyFile, 0); err != nil {
		t.Fatalf("AddKeyToAgent(other): %v", err)
	}
	var buf bytes.Buffer
	keyless := &agevault.Vault{Config: &agevault.Config{
		SecretKeyFile:  filepath.Join(dir, "missing.key"),
		KeyAgentSocket: socket,
	}}
	if err := agevaultCat(keyless, secret+".age", &buf); err == nil {
		t.Fatalf("decrypt with a non-matching agent key succeeded: %q", buf.String())
	}
	// ... so a client whose key file can falls back to it.
	client := &agevault.Vault{Config: &agevault.Config{
		SecretKeyFile:  v.Config.SecretKeyFile,
		RecipientsFile: v.Config.RecipientsFile,
		KeyAgentSocket: socket,
	}}
	if err := agevaultCat(client, secret+".age", &buf); err != nil || buf.String() != "x\n" {
		t.Fatalf("fallback to the key file: %q, %v", buf.String(), err)
	}

	// Adding the right key second: the agent tries every key it holds.
	if _, err := v.AddKeyToAgent(socket, v.Config.SecretKeyFile, 0); err != nil {
		t.Fatalf("AddKeyToAgent: %v", err)
	}
	// Re-adding must not duplicate.
	if _, err := v.AddKeyToAgent(socket, v.Config.SecretKeyFile, 0); err != nil {
		t.Fatalf("re-AddKeyToAgent: %v", err)
	}
	keys, err := keyagent.List(socket)
	if err != nil || len(keys) != 2 {
		t.Fatalf("list: %v, err %v; want 2 keys", keys, err)
	}
	otherPub, _ := other.GetPublicKey()
	if keys[0].PublicKey != otherPub {
		t.Fatalf("list order: first = %s, want first-added %s", keys[0].PublicKey, otherPub)
	}
	if err := agevaultCat(client, secret+".age", &buf); err != nil {
		t.Fatalf("decrypt via second agent key: %v", err)
	}

	// After clear, the client falls back to the key file.
	if err := keyagent.Clear(socket); err != nil {
		t.Fatalf("KeyAgentClear: %v", err)
	}
	if keys, _ := keyagent.List(socket); len(keys) != 0 {
		t.Fatalf("keys after clear: %v", keys)
	}
	wantPub, _ := v.GetPublicKey()
	if pub, err := client.GetPublicKey(); err != nil || pub != wantPub {
		t.Fatalf("fallback GetPublicKey = %s, %v; want %s", pub, err, wantPub)
	}

	// An unreachable agent also falls back.
	client.Config.KeyAgentSocket = filepath.Join(dir, "nope.sock")
	if pub, err := client.GetPublicKey(); err != nil || pub != wantPub {
		t.Fatalf("unreachable-agent GetPublicKey = %s, %v; want %s", pub, err, wantPub)
	}
}

// Who "I" am (pubkey, rotate, --self) is always the key in
// AGE_SECRET_KEY_FILE. The agent only spares the passphrase prompt when it
// verifiably holds that key; it never stands in with another one.
func TestKeyAgentPublicKeyFollowsKeyFile(t *testing.T) {
	v, dir := setupTestEnv(t)
	other, _ := setupTestEnv(t)
	wantPub, _ := v.GetPublicKey()
	otherPub, _ := other.GetPublicKey()
	socket := startKeyAgent(t)

	v.PassphrasePrompt = fixedPassphrase("pw", nil)
	if err := v.SetKeyPassphrase(v.Config.SecretKeyFile); err != nil {
		t.Fatalf("SetKeyPassphrase: %v", err)
	}
	prompts := 0
	clientFor := func(keyFile string, prompt func(string) (string, error)) *agevault.Vault {
		return &agevault.Vault{
			Config:           &agevault.Config{SecretKeyFile: keyFile, KeyAgentSocket: socket},
			PassphrasePrompt: prompt,
		}
	}
	counting := fixedPassphrase("pw", &prompts)

	// The agent holds only someone else's key: it is not taken for mine, the
	// (protected) key file is unlocked instead.
	if _, err := other.AddKeyToAgent(socket, other.Config.SecretKeyFile, 0); err != nil {
		t.Fatalf("AddKeyToAgent(other): %v", err)
	}
	if pub, err := clientFor(v.Config.SecretKeyFile, counting).GetPublicKey(); err != nil || pub != wantPub {
		t.Fatalf("GetPublicKey with a foreign sole agent key = %s, %v; want %s", pub, err, wantPub)
	}
	if prompts != 1 {
		t.Fatalf("prompts = %d, want 1 (key file unlocked)", prompts)
	}
	self := writeFile(t, filepath.Join(dir, "self.txt"), "self\n")
	if err := clientFor(v.Config.SecretKeyFile, counting).Encrypt(true, self); err != nil {
		t.Fatalf("Encrypt --self: %v", err)
	}
	var buf bytes.Buffer
	if err := agevaultCat(other, self+".age", &buf); err == nil {
		t.Fatal("--self file is readable with the agent's foreign key")
	}
	// Decrypting it: no agent key fits, so the key file is tried.
	prompts = 0
	if err := agevaultCat(clientFor(v.Config.SecretKeyFile, counting), self+".age", &buf); err != nil || buf.String() != "self\n" {
		t.Fatalf("decrypt falling back to the key file: %q, %v", buf.String(), err)
	}
	if prompts != 1 {
		t.Fatalf("prompts = %d, want 1", prompts)
	}

	// Once my key is in the agent too (added second, through a symlink), it is
	// recognised by content: no prompt, whatever name the file is reached by.
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(v.Config.SecretKeyFile, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := v.AddKeyToAgent(socket, link, 0); err != nil {
		t.Fatalf("AddKeyToAgent: %v", err)
	}
	keys, err := keyagent.List(socket)
	if err != nil || len(keys) != 2 {
		t.Fatalf("list: %v, err %v; want 2 keys", keys, err)
	}
	if resolved, _ := filepath.EvalSymlinks(link); keys[1].Source != resolved {
		t.Fatalf("source = %q, want the resolved key file %q", keys[1].Source, resolved)
	}
	copied := writeFile(t, filepath.Join(dir, "copy.key"), readFile(t, v.Config.SecretKeyFile))
	for _, keyFile := range []string{v.Config.SecretKeyFile, link, copied} {
		c := clientFor(keyFile, noPrompt(t))
		if pub, err := c.GetPublicKey(); err != nil || pub != wantPub {
			t.Errorf("%s: GetPublicKey = %s, %v; want %s", keyFile, pub, err, wantPub)
		}
	}
	if pub, err := clientFor(other.Config.SecretKeyFile, noPrompt(t)).GetPublicKey(); err != nil || pub != otherPub {
		t.Fatalf("GetPublicKey for the other key file = %s, %v; want %s", pub, err, otherPub)
	}

	// A different key at the same path is not the key the agent holds.
	replaced, _ := setupTestEnv(t)
	replacedPub, _ := replaced.GetPublicKey()
	writeFile(t, copied, readFile(t, replaced.Config.SecretKeyFile))
	if pub, err := clientFor(copied, noPrompt(t)).GetPublicKey(); err != nil || pub != replacedPub {
		t.Fatalf("GetPublicKey after the key file was replaced = %s, %v; want %s", pub, err, replacedPub)
	}

	// No key file at all: the agent still decrypts, but nothing says who I am.
	keyless := clientFor(filepath.Join(dir, "missing.key"), noPrompt(t))
	if err := agevaultCat(keyless, self+".age", &buf); err != nil || buf.String() != "self\n" {
		t.Fatalf("decrypt without a key file: %q, %v", buf.String(), err)
	}
	if pub, err := keyless.GetPublicKey(); err == nil {
		t.Fatalf("GetPublicKey without a key file = %s, want an error", pub)
	}
	if err := keyless.Encrypt(true, writeFile(t, filepath.Join(dir, "amb.txt"), "x\n")); err == nil {
		t.Fatal("Encrypt --self without a key file succeeded")
	}

	// A key added without its file is for decryption only.
	if err := keyagent.Clear(socket); err != nil {
		t.Fatalf("KeyAgentClear: %v", err)
	}
	keyData, err := os.ReadFile(other.Config.SecretKeyFile)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if _, err := keyagent.Add(socket, keyData, 0); err != nil {
		t.Fatalf("KeyAgentAdd: %v", err)
	}
	if pub, err := keyless.GetPublicKey(); err == nil {
		t.Fatalf("GetPublicKey from a sole agent key without a key file = %s, want an error", pub)
	}
}

// agevaultCat decrypts file through v into buf without touching os.Stdout.
func agevaultCat(v *agevault.Vault, file string, buf *bytes.Buffer) error {
	id, err := v.GetIdentity()
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	buf.Reset()
	return agevault.DecryptToWriter(buf, f, id)
}

func TestKeyAgentLifetime(t *testing.T) {
	v, _ := setupTestEnv(t)
	socket := startKeyAgent(t)

	if _, err := v.AddKeyToAgent(socket, v.Config.SecretKeyFile, time.Second); err != nil {
		t.Fatalf("AddKeyToAgent: %v", err)
	}
	keys, err := keyagent.List(socket)
	if err != nil || len(keys) != 1 || keys[0].Expires == nil {
		t.Fatalf("list: %+v, err %v; want one key with an expiry", keys, err)
	}
	time.Sleep(1200 * time.Millisecond)
	if keys, _ := keyagent.List(socket); len(keys) != 0 {
		t.Fatalf("key still present after its lifetime: %+v", keys)
	}
}

func TestKeyAgentRejectsSecondInstanceAndBadKey(t *testing.T) {
	socket := startKeyAgent(t)

	err := new(keyagent.Agent).Serve(context.Background(), socket)
	if err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("second agent on the same socket: err %v", err)
	}
	// The running agent must be unaffected.
	if _, err := keyagent.List(socket); err != nil {
		t.Fatalf("first agent broken by second start: %v", err)
	}

	if _, err := keyagent.Add(socket, []byte("not a key\n"), 0); err == nil {
		t.Fatal("adding garbage succeeded")
	}
	if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %v (err %v), want 0600", info.Mode().Perm(), err)
	}
}

var (
	e2eAgentBinOnce sync.Once
	e2eAgentBinPath string
	e2eAgentBinErr  error
)

func buildKeyAgentBinary(t *testing.T) string {
	t.Helper()
	e2eAgentBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "agevault-agent-e2e-bin-*")
		if err != nil {
			e2eAgentBinErr = err
			return
		}
		e2eAgentBinPath = filepath.Join(dir, "agevault-agent")
		cmd := exec.Command("go", "build", "-o", e2eAgentBinPath, "./cmd/agevault-agent")
		if out, err := cmd.CombinedOutput(); err != nil {
			e2eAgentBinErr = fmt.Errorf("build agevault-agent binary: %w\n%s", err, out)
		}
	})
	if e2eAgentBinErr != nil {
		t.Fatalf("%v", e2eAgentBinErr)
	}
	return e2eAgentBinPath
}

// The two real binaries together: agevault-agent serve/add/list/clear, and
// agevault decrypting through it with no key file of its own.
func TestE2E_KeyAgent(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	agentBin := buildKeyAgentBinary(t)
	v, dir := setupTestEnv(t)
	wantPub, _ := v.GetPublicKey()

	secret := writeFile(t, filepath.Join(dir, "secret.txt"), "e2e agent\n")
	if err := v.Encrypt(false, secret); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	socket := filepath.Join(dir, "ka.sock")
	agentEnv := baseEnv("AGE_KEY_AGENT_SOCKET=" + socket)

	serve := exec.Command(agentBin, "serve")
	serve.Env = agentEnv
	var serveLog bytes.Buffer
	serve.Stderr = &serveLog
	if err := serve.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = serve.Process.Signal(syscall.SIGTERM)
		_ = serve.Wait()
	}
	t.Cleanup(stop)
	waitForKeyAgent(t, socket)

	if _, stderr, err := runCLI(t, agentBin, dir, agentEnv, "list"); err == nil || !strings.Contains(stderr, "no keys") {
		t.Fatalf("list on empty agent: err %v, stderr %q", err, stderr)
	}
	if _, stderr, err := runCLI(t, agentBin, dir, agentEnv, "add", "-t", "1h", v.Config.SecretKeyFile); err != nil {
		t.Fatalf("add: %v\n%s", err, stderr)
	}
	keyPath, err := filepath.EvalSymlinks(v.Config.SecretKeyFile)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	stdout, stderr, err := runCLI(t, agentBin, dir, agentEnv, "list")
	if err != nil || !strings.HasPrefix(stdout, wantPub+"\t"+keyPath+"\t(expires in ") {
		t.Fatalf("list: %q, err %v, stderr %q", stdout, err, stderr)
	}

	// The client has the agent socket but its key file does not exist.
	clientEnv := baseEnv(
		"AGE_KEY_AGENT_SOCKET="+socket,
		"AGE_SECRET_KEY_FILE="+filepath.Join(dir, "missing.key"),
	)
	stdout, stderr, err = runCLI(t, bin, dir, clientEnv, "cat", secret+".age")
	if err != nil || stdout != "e2e agent\n" {
		t.Fatalf("cat via agent: %q, err %v, stderr %q", stdout, err, stderr)
	}
	// Decrypting needs no key file, but nothing else says who "I" am.
	if stdout, stderr, err = runCLI(t, bin, dir, clientEnv, "pubkey"); err == nil || !strings.Contains(stderr, "AGE_SECRET_KEY_FILE") {
		t.Fatalf("pubkey without a key file: %q, err %v, stderr %q", stdout, err, stderr)
	}
	withKeyFile := baseEnv(
		"AGE_KEY_AGENT_SOCKET="+socket,
		"AGE_SECRET_KEY_FILE="+v.Config.SecretKeyFile,
	)
	stdout, stderr, err = runCLI(t, bin, dir, withKeyFile, "pubkey")
	if err != nil || strings.TrimSpace(stdout) != wantPub {
		t.Fatalf("pubkey via agent: %q, err %v, stderr %q", stdout, err, stderr)
	}

	if _, stderr, err := runCLI(t, agentBin, dir, agentEnv, "clear"); err != nil {
		t.Fatalf("clear: %v\n%s", err, stderr)
	}
	if _, _, err := runCLI(t, bin, dir, clientEnv, "cat", secret+".age"); err == nil {
		t.Fatal("cat succeeded after the agent was cleared and with no key file")
	}

	stop()
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket not removed on shutdown (err %v); agent log:\n%s", err, serveLog.String())
	}
}
