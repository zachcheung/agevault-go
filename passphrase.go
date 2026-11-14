package agevault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/term"
)

// ageFileIntro is the first line of a binary (non-armored) age file.
const ageFileIntro = "age-encryption.org/v1\n"

// isEncryptedKey reports whether key file content is an age-encrypted file
// (armored or binary) rather than a plaintext age-keygen identity file.
func isEncryptedKey(data []byte) bool {
	if bytes.HasPrefix(data, []byte(ageFileIntro)) {
		return true
	}
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte(armor.Header))
}

// ttyPassphrasePrompt reads a passphrase from the controlling terminal with
// echo disabled. It talks to /dev/tty rather than stdin/stderr so it keeps
// working when those are pipes (e.g. 'agevault cat x.age | ...').
func ttyPassphrasePrompt(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal available to prompt for the passphrase: %w", err)
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return string(pass), nil
}

func (v *Vault) promptPassphrase(prompt string) (string, error) {
	if v.PassphrasePrompt != nil {
		return v.PassphrasePrompt(prompt)
	}
	return ttyPassphrasePrompt(prompt)
}

// promptNewPassphrase asks for a new passphrase twice and rejects an empty
// or mismatched one.
func (v *Vault) promptNewPassphrase(path string) (string, error) {
	pass, err := v.promptPassphrase(fmt.Sprintf("Enter new passphrase for %s: ", path))
	if err != nil {
		return "", err
	}
	if pass == "" {
		return "", fmt.Errorf("passphrase must not be empty")
	}
	confirm, err := v.promptPassphrase("Confirm new passphrase: ")
	if err != nil {
		return "", err
	}
	if pass != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}
	return pass, nil
}

// encryptKeyData encrypts key file content with a passphrase (scrypt),
// ASCII-armored — the same format 'age -p -a' produces, so the result is
// also usable as an identity file with the age CLI.
func encryptKeyData(plain []byte, passphrase string) ([]byte, error) {
	rec, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, rec)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// decryptKeyData decrypts passphrase-encrypted key file content (armored or
// binary).
func decryptKeyData(data []byte, passphrase string) ([]byte, error) {
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	var src io.Reader = bytes.NewReader(data)
	if !bytes.HasPrefix(data, []byte(ageFileIntro)) {
		src = armor.NewReader(src)
	}
	r, err := age.Decrypt(src, id)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, fmt.Errorf("incorrect passphrase, or not a passphrase-encrypted file")
		}
		return nil, err
	}
	return io.ReadAll(r)
}

// readKeyFile returns the plaintext content of a key file, prompting for the
// passphrase when the file is passphrase-encrypted. encrypted reports which
// of the two it was.
func (v *Vault) readKeyFile(path string) (plain []byte, encrypted bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("open key file %s: %w", path, err)
	}
	if !isEncryptedKey(data) {
		return data, false, nil
	}
	pass, err := v.promptPassphrase(fmt.Sprintf("Enter passphrase for %s: ", path))
	if err != nil {
		return nil, true, fmt.Errorf("key file %s is passphrase-protected: %w", path, err)
	}
	plain, err = decryptKeyData(data, pass)
	if err != nil {
		return nil, true, fmt.Errorf("decrypt key file %s: %w", path, err)
	}
	return plain, true, nil
}

// loadIdentityFile loads the first identity from a key file, which may be a
// plaintext age-keygen file or a passphrase-encrypted one. An identity
// unlocked with a passphrase is cached on the Vault, so a command touching
// many files (reencrypt --all, rotate, agent) prompts only once.
func (v *Vault) loadIdentityFile(path string) (age.Identity, error) {
	if id, ok := v.unlockedIdentities[path]; ok {
		return id, nil
	}
	plain, encrypted, err := v.readKeyFile(path)
	if err != nil {
		return nil, err
	}
	ids, err := age.ParseIdentities(bytes.NewReader(plain))
	if err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found in %s", path)
	}
	if encrypted {
		if v.unlockedIdentities == nil {
			v.unlockedIdentities = make(map[string]age.Identity)
		}
		v.unlockedIdentities[path] = ids[0]
	}
	return ids[0], nil
}

// generateKeyFileContent generates a new identity and returns its public key
// and its age-keygen-format key file content.
func generateKeyFileContent(pq bool) (pubKey string, content []byte, err error) {
	var buf bytes.Buffer
	pubKey, err = KeygenToWriter(pq, &buf)
	if err != nil {
		return "", nil, err
	}
	return pubKey, buf.Bytes(), nil
}

// KeygenProtectedToWriter generates a new identity, prompts for a new
// passphrase, and writes the passphrase-encrypted key to w. The plaintext
// key only ever exists in memory. Returns the public key string.
func (v *Vault) KeygenProtectedToWriter(pq bool, w io.Writer, name string) (string, error) {
	pass, err := v.promptNewPassphrase(name)
	if err != nil {
		return "", err
	}
	pubKey, content, err := generateKeyFileContent(pq)
	if err != nil {
		return "", err
	}
	enc, err := encryptKeyData(content, pass)
	if err != nil {
		return "", fmt.Errorf("encrypt key: %w", err)
	}
	if _, err := w.Write(enc); err != nil {
		return "", err
	}
	return pubKey, nil
}

// GenerateProtectedIdentityFile generates a new identity and writes it to
// path passphrase-encrypted, failing if path already exists. Parent
// directories are created with mode 0700 as needed. Returns the public key.
func (v *Vault) GenerateProtectedIdentityFile(path string, pq bool) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("key file already exists: %s", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create key directory %s: %w", dir, err)
	}
	var buf bytes.Buffer
	pubKey, err := v.KeygenProtectedToWriter(pq, &buf, path)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("create key file %s: %w", path, err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return "", fmt.Errorf("write key file %s: %w", path, err)
	}
	return pubKey, f.Close()
}

// SetKeyPassphrase passphrase-protects an existing plaintext key file, or
// changes the passphrase of an already protected one (prompting for the
// current passphrase first). The file is replaced atomically. If path is a
// symlink, the file it points to is the one replaced and the link is kept.
func (v *Vault) SetKeyPassphrase(path string) error {
	// Resolve symlinks first: renaming over path itself would swap the link
	// for a regular file and leave the real key file untouched.
	path, err := replaceTarget(path)
	if err != nil {
		return err
	}
	plain, encrypted, err := v.readKeyFile(path)
	if err != nil {
		return err
	}
	ids, err := age.ParseIdentities(bytes.NewReader(plain))
	if err != nil {
		return fmt.Errorf("parse key file %s: %w", path, err)
	}
	if len(ids) == 0 {
		return fmt.Errorf("no identities found in %s", path)
	}

	pass, err := v.promptNewPassphrase(path)
	if err != nil {
		return err
	}
	enc, err := encryptKeyData(plain, pass)
	if err != nil {
		return fmt.Errorf("encrypt key: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".agevault.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(enc); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	// Flush to disk before the rename: this may be the only copy of the key,
	// so a crash must leave either the old file or the complete new one.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	delete(v.unlockedIdentities, path)

	if encrypted {
		fmt.Fprintf(os.Stderr, "Passphrase changed for '%s'.\n", path)
	} else {
		fmt.Fprintf(os.Stderr, "'%s' is now passphrase-protected.\n", path)
	}
	return nil
}
