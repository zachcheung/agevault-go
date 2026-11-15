package agevault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agevault "github.com/zachcheung/agevault-go"
)

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestEncryptRemoveSource(t *testing.T) {
	v, dir := setupTestEnv(t)
	remove := agevault.EncryptOptions{RemoveSource: true}

	t.Run("removes after encrypting", func(t *testing.T) {
		a := writeFile(t, filepath.Join(dir, "a.txt"), "aaa\n")
		b := writeFile(t, filepath.Join(dir, "b.txt"), "bbb\n")
		if err := v.EncryptWithOptions(remove, a, b); err != nil {
			t.Fatalf("EncryptWithOptions: %v", err)
		}
		if exists(a) || exists(b) {
			t.Fatal("source files were not removed")
		}
		if err := v.Decrypt(a+".age", b+".age"); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if readFile(t, a) != "aaa\n" || readFile(t, b) != "bbb\n" {
			t.Fatal("decrypted content does not match the removed sources")
		}
	})

	t.Run("self", func(t *testing.T) {
		src := writeFile(t, filepath.Join(dir, "self.txt"), "self\n")
		if err := v.EncryptWithOptions(agevault.EncryptOptions{Self: true, RemoveSource: true}, src); err != nil {
			t.Fatalf("EncryptWithOptions: %v", err)
		}
		if exists(src) {
			t.Fatal("source file was not removed")
		}
	})

	t.Run("kept without the option", func(t *testing.T) {
		src := writeFile(t, filepath.Join(dir, "keep.txt"), "keep\n")
		if err := v.Encrypt(false, src); err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if !exists(src) {
			t.Fatal("source file was removed without RemoveSource")
		}
	})

	t.Run("kept when encryption fails", func(t *testing.T) {
		// No recipients file can be resolved, so nothing gets encrypted.
		broken := &agevault.Vault{Config: &agevault.Config{
			SecretKeyFile:  v.Config.SecretKeyFile,
			RecipientsFile: filepath.Join(dir, "no-such-recipients.txt"),
		}}
		src := writeFile(t, filepath.Join(dir, "fail.txt"), "precious\n")
		if err := broken.EncryptWithOptions(remove, src); err == nil {
			t.Fatal("encryption without recipients succeeded")
		}
		if got := readFile(t, src); got != "precious\n" {
			t.Fatalf("source after failed encryption = %q", got)
		}
		if exists(src + ".age") {
			t.Fatal("a .age file was left behind by the failed encryption")
		}
	})

	t.Run("symlinked source", func(t *testing.T) {
		// Removing only the link would leave the plaintext on disk.
		realFile := writeFile(t, filepath.Join(dir, "real-plain.txt"), "linked\n")
		link := filepath.Join(dir, "link.txt")
		if err := os.Symlink("real-plain.txt", link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := v.EncryptWithOptions(remove, link); err != nil {
			t.Fatalf("EncryptWithOptions: %v", err)
		}
		if exists(link) || exists(realFile) {
			t.Fatalf("plaintext left behind: link %v, target %v", exists(link), exists(realFile))
		}
		if err := v.Decrypt(link + ".age"); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if got := readFile(t, link); got != "linked\n" {
			t.Fatalf("decrypted content = %q", got)
		}
	})
}

func TestE2E_EncryptRemove(t *testing.T) {
	t.Parallel()
	bin := buildAgevaultBinary(t)
	v, dir := setupTestEnv(t)
	env := baseEnv(
		"AGE_SECRET_KEY_FILE="+v.Config.SecretKeyFile,
		"AGE_RECIPIENTS_FILE="+v.Config.RecipientsFile,
	)

	src := writeFile(t, filepath.Join(dir, "cli.txt"), "cli\n")
	stdout, stderr, err := runCLI(t, bin, dir, env, "encrypt", "--remove", src)
	if err != nil {
		t.Fatalf("encrypt --remove: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "and removed.") {
		t.Fatalf("stdout = %q, want it to say the source was removed", stdout)
	}
	if exists(src) {
		t.Fatal("source file was not removed")
	}
	stdout, stderr, err = runCLI(t, bin, dir, env, "cat", src+".age")
	if err != nil || stdout != "cli\n" {
		t.Fatalf("cat: %q, err %v, stderr %q", stdout, err, stderr)
	}
}
