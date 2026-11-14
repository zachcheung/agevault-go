package agevault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agevault "github.com/zachcheung/agevault-go"
)

// assertStillSymlink fails if link is no longer a symlink, i.e. an atomic
// replace renamed over the link instead of the file it points to.
func assertStillSymlink(t *testing.T, link string) {
	t.Helper()
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat %s: %v", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s was replaced by a regular file", link)
	}
}

// Every command that replaces a file atomically must, when given a symlink,
// replace the file the link points to and keep the link.
func TestAtomicWritesFollowSymlinks(t *testing.T) {
	v, dir := setupTestEnv(t)
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}

	// real/secret.txt.age, reached through the link ./secret.txt.age.
	plain := writeFile(t, filepath.Join(realDir, "secret.txt"), "one\n")
	if err := v.Encrypt(false, plain); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	os.Remove(plain)
	realAge := plain + ".age"
	linkAge := filepath.Join(dir, "secret.txt.age")
	if err := os.Symlink(filepath.Join("real", "secret.txt.age"), linkAge); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	t.Run("reencrypt", func(t *testing.T) {
		before := readFile(t, realAge)
		if err := v.Reencrypt(false, linkAge); err != nil {
			t.Fatalf("Reencrypt: %v", err)
		}
		assertStillSymlink(t, linkAge)
		if readFile(t, realAge) == before {
			t.Fatal("the link's target was not re-encrypted")
		}
	})

	t.Run("edit", func(t *testing.T) {
		script := filepath.Join(dir, "editor.sh")
		writeFile(t, script, "#!/bin/sh\necho two >> \"$1\"\n")
		os.Chmod(script, 0755)
		t.Setenv("EDITOR", script)

		if err := v.Edit(false, linkAge); err != nil {
			t.Fatalf("Edit: %v", err)
		}
		assertStillSymlink(t, linkAge)
		if err := v.Decrypt(realAge); err != nil {
			t.Fatalf("Decrypt target after edit: %v", err)
		}
		if got := readFile(t, plain); got != "one\ntwo\n" {
			t.Fatalf("target content after edit = %q", got)
		}
		os.Remove(plain)
	})

	t.Run("decrypt", func(t *testing.T) {
		// ./secret.txt is a link to an existing real/out.txt.
		realOut := writeFile(t, filepath.Join(realDir, "out.txt"), "stale\n")
		linkOut := filepath.Join(dir, "secret.txt")
		if err := os.Symlink(filepath.Join("real", "out.txt"), linkOut); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := v.Decrypt(linkAge); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		assertStillSymlink(t, linkOut)
		if got := readFile(t, realOut); got != "one\ntwo\n" {
			t.Fatalf("decrypt target content = %q", got)
		}
	})

	t.Run("encrypt", func(t *testing.T) {
		// Encrypting ./new.txt writes ./new.txt.age, itself a link.
		src := writeFile(t, filepath.Join(dir, "new.txt"), "fresh\n")
		realNew := writeFile(t, filepath.Join(realDir, "new.txt.age"), "placeholder")
		linkNew := src + ".age"
		if err := os.Symlink(filepath.Join("real", "new.txt.age"), linkNew); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := v.Encrypt(false, src); err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		assertStillSymlink(t, linkNew)
		if got := readFile(t, realNew); !strings.HasPrefix(got, "age-encryption.org/v1") {
			t.Fatalf("encrypt target was not replaced: %q", got)
		}
	})

	t.Run("agent bundle", func(t *testing.T) {
		realCert := writeFile(t, filepath.Join(realDir, "cert.pem"), "old\n")
		dest := filepath.Join(dir, "dest")
		if err := os.Mkdir(dest, 0700); err != nil {
			t.Fatal(err)
		}
		linkCert := filepath.Join(dest, "cert.pem")
		if err := os.Symlink(realCert, linkCert); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		bundle := &agevault.AgentBundle{Files: map[string][]byte{"cert.pem": []byte("new\n")}}
		if _, err := agevault.ApplyAgentBundle(bundle, nil, dest); err != nil {
			t.Fatalf("ApplyAgentBundle: %v", err)
		}
		assertStillSymlink(t, linkCert)
		if got := readFile(t, realCert); got != "new\n" {
			t.Fatalf("bundle target content = %q", got)
		}
	})

	t.Run("dangling link", func(t *testing.T) {
		// The link points at a file that does not exist yet: the write
		// creates that file and the link stays a link.
		src := writeFile(t, filepath.Join(dir, "dangling.txt"), "d\n")
		link := src + ".age"
		realFile := filepath.Join(realDir, "dangling.txt.age")
		if err := os.Symlink(filepath.Join("real", "dangling.txt.age"), link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := v.Encrypt(false, src); err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		assertStillSymlink(t, link)
		if got := readFile(t, realFile); !strings.HasPrefix(got, "age-encryption.org/v1") {
			t.Fatalf("dangling link target was not created: %q", got)
		}

		// A link into a directory that does not exist cannot be written
		// through; that is an error, and the link is still left alone.
		src2 := writeFile(t, filepath.Join(dir, "nodir.txt"), "n\n")
		link2 := src2 + ".age"
		if err := os.Symlink(filepath.Join("missing-dir", "nodir.txt.age"), link2); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := v.Encrypt(false, src2); err == nil {
			t.Fatal("Encrypt through a link into a missing directory succeeded")
		}
		assertStillSymlink(t, link2)
	})

	t.Run("link loop", func(t *testing.T) {
		src := writeFile(t, filepath.Join(dir, "loop.txt"), "l\n")
		a, b := src+".age", filepath.Join(dir, "loop-b")
		if err := os.Symlink("loop-b", a); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := os.Symlink("loop.txt.age", b); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		err := v.Encrypt(false, src)
		if err == nil || !strings.Contains(err.Error(), "too many levels of symbolic links") {
			t.Fatalf("Encrypt onto a link loop: err %v", err)
		}
		assertStillSymlink(t, a)
		assertStillSymlink(t, b)
	})

	// No temp files may be left next to the links or their targets.
	for _, d := range []string{dir, realDir} {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if strings.Contains(e.Name(), ".agevault.") {
				t.Errorf("stray temp file %s in %s", e.Name(), d)
			}
		}
	}
}
