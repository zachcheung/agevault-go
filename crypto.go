package agevault

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// GetIdentity returns the age identity (private key) from config.
// Precedence: KMS (auto-detected or AGE_KMS_PROVIDER) > AGE_SECRET_KEY > AGE_SECRET_KEY_FILE.
func (v *Vault) GetIdentity() (age.Identity, error) {
	provider, ciphertext, err := v.resolveKMS()
	if err != nil {
		return nil, err
	}
	if ciphertext != "" {
		dec := v.KMSDecryptor
		if dec == nil {
			dec, err = v.newKMSDecryptor(provider)
			if err != nil {
				return nil, err
			}
		}
		return decryptIdentityFromKMS(context.Background(), dec, ciphertext)
	}
	if v.Config.SecretKey != "" {
		ids, err := age.ParseIdentities(strings.NewReader(v.Config.SecretKey))
		if err != nil {
			return nil, fmt.Errorf("parse AGE_SECRET_KEY: %w", err)
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("no identities found in AGE_SECRET_KEY")
		}
		return ids[0], nil
	}

	f, err := os.Open(v.Config.SecretKeyFile)
	if err != nil {
		return nil, fmt.Errorf("open key file %s: %w", v.Config.SecretKeyFile, err)
	}
	defer f.Close()

	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", v.Config.SecretKeyFile, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found in %s", v.Config.SecretKeyFile)
	}
	return ids[0], nil
}

// GetPublicKey returns the public key string for the current identity.
func (v *Vault) GetPublicKey() (string, error) {
	id, err := v.GetIdentity()
	if err != nil {
		return "", err
	}
	return identityPublicKey(id)
}

func identityPublicKey(id age.Identity) (string, error) {
	switch id := id.(type) {
	case *age.X25519Identity:
		return id.Recipient().String(), nil
	case *age.HybridIdentity:
		return id.Recipient().String(), nil
	default:
		return "", fmt.Errorf("unsupported identity type %T", id)
	}
}

// GetRecipientsFilePath resolves the recipients file path for a given secret file.
// Returns empty string when AGE_RECIPIENTS env is set (inline recipients).
func (v *Vault) GetRecipientsFilePath(secretFile string) (string, error) {
	if v.Config.Recipients != "" {
		return "", nil
	}

	rf := v.Config.RecipientsFile
	// If no path separator in rf, look for it alongside the secret file.
	if !filepath.IsAbs(rf) && !strings.Contains(rf, string(filepath.Separator)) {
		rf = filepath.Join(filepath.Dir(secretFile), rf)
	}

	if _, err := os.Stat(rf); os.IsNotExist(err) {
		return "", fmt.Errorf("AGE_RECIPIENTS is not set, and '%s' not found", rf)
	} else if err != nil {
		return "", fmt.Errorf("stat recipients file '%s': %w", rf, err)
	}

	// Verify it's readable.
	fh, err := os.Open(rf)
	if err != nil {
		return "", fmt.Errorf("AGE_RECIPIENTS is not set, and '%s' is not readable", rf)
	}
	fh.Close()

	return rf, nil
}

// GetRecipients returns age recipients for the given secret file, from either
// the AGE_RECIPIENTS env var or the resolved recipients file.
func (v *Vault) GetRecipients(secretFile string) ([]age.Recipient, error) {
	if v.Config.Recipients != "" {
		return parseRecipientsFromStrings(strings.Split(v.Config.Recipients, ","))
	}
	rf, err := v.GetRecipientsFilePath(secretFile)
	if err != nil {
		return nil, err
	}
	return ParseRecipientsFile(rf)
}

// ParseRecipientsFile reads and parses age public keys from a file.
// Lines beginning with '#' and blank lines are ignored.
func ParseRecipientsFile(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open recipients file %s: %w", path, err)
	}
	defer f.Close()
	return parseRecipientsReader(f)
}

func parseRecipientsReader(r io.Reader) ([]age.Recipient, error) {
	var recipients []age.Recipient
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		rec, err := parseRecipient(line)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, rec)
	}
	return recipients, scanner.Err()
}

func parseRecipientsFromStrings(ss []string) ([]age.Recipient, error) {
	var recipients []age.Recipient
	seen := make(map[string]bool)
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		rec, err := parseRecipient(s)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, rec)
	}
	return recipients, nil
}

func parseRecipient(s string) (age.Recipient, error) {
	if strings.HasPrefix(s, "age1pq1") {
		rec, err := age.ParseHybridRecipient(s)
		if err != nil {
			return nil, fmt.Errorf("parse recipient %q: %w", s, err)
		}
		return rec, nil
	}
	rec, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("parse recipient %q: %w", s, err)
	}
	return rec, nil
}

// EncryptToFile streams plaintext from src into dst, encrypted for the given recipients.
func EncryptToFile(dst io.Writer, src io.Reader, recipients []age.Recipient) error {
	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return fmt.Errorf("create encryptor: %w", err)
	}
	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("encrypt data: %w", err)
	}
	return w.Close()
}

// DecryptToWriter decrypts age-encrypted data from src and writes plaintext to w.
func DecryptToWriter(w io.Writer, src io.Reader, identity age.Identity) error {
	r, err := age.Decrypt(src, identity)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, r)
	return err
}

// GenerateIdentity creates a new X25519 key pair and writes the private key to path
// in age-keygen format. Parent directories are created with mode 0700 as needed.
func GenerateIdentity(path string) (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	return identity, writeIdentityFile(path, identity.Recipient().String(), identity.String())
}

// GenerateHybridIdentityToFile creates a new ML-KEM-768+X25519 hybrid key pair and
// writes the private key to path. Parent directories are created with mode 0700 as needed.
func GenerateHybridIdentityToFile(path string) (*age.HybridIdentity, error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate hybrid identity: %w", err)
	}
	return identity, writeIdentityFile(path, identity.Recipient().String(), identity.String())
}

// KeygenToWriter generates a new age identity and writes it in age-keygen
// format to w. Returns the public key string.
func KeygenToWriter(pq bool, w io.Writer) (string, error) {
	var pubKey, secretKey string
	if pq {
		id, err := age.GenerateHybridIdentity()
		if err != nil {
			return "", fmt.Errorf("generate identity: %w", err)
		}
		pubKey, secretKey = id.Recipient().String(), id.String()
	} else {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return "", fmt.Errorf("generate identity: %w", err)
		}
		pubKey, secretKey = id.Recipient().String(), id.String()
	}
	writeKeyFormat(w, pubKey, secretKey)
	return pubKey, nil
}

func writeKeyFormat(w io.Writer, pubKey, secretKey string) {
	fmt.Fprintf(w, "# created: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "# public key: %s\n", pubKey)
	fmt.Fprintf(w, "%s\n", secretKey)
}

// PublicKeyFromFile reads an age private key file and returns its public key.
func PublicKeyFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(data)))
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no identities in %s", path)
	}
	return identityPublicKey(ids[0])
}

func writeIdentityFile(path, pubKey, secretKey string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key directory %s: %w", dir, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create key file %s: %w", path, err)
	}
	defer f.Close()
	writeKeyFormat(f, pubKey, secretKey)
	return nil
}
