package agevault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// stdinStdoutSentinel, passed in place of a file path, means "read plaintext
// from stdin / write ciphertext to stdout" for Encrypt, or "read ciphertext
// from stdin / write plaintext to stdout" for Decrypt-like commands.
const stdinStdoutSentinel = "-"

// Encrypt encrypts one or more plaintext files, writing <file>.age output.
// If self is true, the current identity is used as the sole recipient (no
// recipients file needed). Otherwise, recipients are loaded from config.
// A file argument of "-" reads plaintext from stdin and writes ciphertext
// to stdout instead of <file>.age; recipients are still resolved (relative
// to the current directory, since there is no file path to resolve
// alongside) unless --self is used.
func (v *Vault) Encrypt(self bool, files ...string) error {
	if len(files) == 0 {
		return fmt.Errorf("missing files")
	}
	if self {
		return v.encryptSelf(files...)
	}
	return v.encryptWithRecipients(files...)
}

func (v *Vault) encryptSelf(files ...string) error {
	id, err := v.GetIdentity()
	if err != nil {
		return fmt.Errorf("--self encryption requires a valid identity: %w", err)
	}
	var selfRecipient age.Recipient
	switch id := id.(type) {
	case *age.X25519Identity:
		selfRecipient = id.Recipient()
	case *age.HybridIdentity:
		selfRecipient = id.Recipient()
	default:
		return fmt.Errorf("unsupported identity type %T for --self", id)
	}
	recipients := []age.Recipient{selfRecipient}

	for _, f := range files {
		if f == stdinStdoutSentinel {
			if err := encryptStdinToStdout(recipients); err != nil {
				return err
			}
			continue
		}
		outFile := f + ".age"
		if _, err := os.Stat(outFile); err == nil {
			fmt.Fprintf(os.Stderr, "[WARN] '%s' already exists.\n", outFile)
		}
		if err := encryptFileToPath(f, outFile, recipients); err != nil {
			return err
		}
		fmt.Printf("'%s' is encrypted to '%s'.\n", f, outFile)
	}
	return nil
}

func (v *Vault) encryptWithRecipients(files ...string) error {
	for _, f := range files {
		if f == stdinStdoutSentinel {
			recipients, err := v.GetRecipients(".")
			if err != nil {
				return err
			}
			if err := encryptStdinToStdout(recipients); err != nil {
				return err
			}
			continue
		}
		outFile := f + ".age"
		if _, err := os.Stat(outFile); err == nil {
			fmt.Fprintf(os.Stderr, "[WARN] '%s' already exists.\n", outFile)
		}
		recipients, err := v.GetRecipients(f)
		if err != nil {
			return err
		}
		if err := encryptFileToPath(f, outFile, recipients); err != nil {
			return err
		}
		fmt.Printf("'%s' is encrypted to '%s'.\n", f, outFile)
	}
	return nil
}

// encryptStdinToStdout streams stdin straight to stdout as ciphertext, with
// no temp file/rename (stdout isn't a file that needs atomic replacement).
// The status message goes to stderr so stdout stays pure ciphertext.
func encryptStdinToStdout(recipients []age.Recipient) error {
	if err := EncryptToFile(os.Stdout, os.Stdin, recipients); err != nil {
		return fmt.Errorf("encrypt stdin: %w", err)
	}
	fmt.Fprintln(os.Stderr, "stdin is encrypted to stdout.")
	return nil
}

// encryptFileToPath encrypts src to dst atomically via a temp file.
func encryptFileToPath(src, dst string, recipients []age.Recipient) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".agevault.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if err := EncryptToFile(tmp, in, recipients); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("encrypt %s: %w", src, err)
	}
	tmp.Close()

	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// DecryptToStdout decrypts a .age file to stdout using the configured identity.
func (v *Vault) DecryptToStdout(file string) error {
	identity, err := v.GetIdentity()
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer f.Close()
	return DecryptToWriter(os.Stdout, f, identity)
}

// decryptToWriter is the internal helper that decrypts src to any writer.
func (v *Vault) decryptToWriter(w io.Writer, file string) error {
	identity, err := v.GetIdentity()
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer f.Close()
	return DecryptToWriter(w, f, identity)
}

// Decrypt decrypts one or more .age files to their original paths (strips .age).
func (v *Vault) Decrypt(files ...string) error {
	if len(files) == 0 {
		return fmt.Errorf("missing files")
	}

	for _, f := range files {
		if !strings.HasSuffix(f, ".age") {
			fmt.Fprintf(os.Stderr, "'%s' is not a .age file.\n", f)
			continue
		}
		dest := strings.TrimSuffix(f, ".age")
		if _, err := os.Stat(dest); err == nil {
			fmt.Fprintf(os.Stderr, "[WARN] '%s' already exists.\n", dest)
		}

		dir := filepath.Dir(dest)
		if dir == "" {
			dir = "."
		}
		tmp, err := os.CreateTemp(dir, ".agevault.*.tmp")
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
		tmpName := tmp.Name()

		if err := v.decryptToWriter(tmp, f); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("decrypt %s: %w", f, err)
		}
		tmp.Close()

		if err := os.Rename(tmpName, dest); err != nil {
			os.Remove(tmpName)
			return fmt.Errorf("move decrypted file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "'%s' is decrypted to '%s'.\n", f, dest)
	}
	return nil
}

// Cat decrypts one or more .age files and writes their plaintext to stdout.
func (v *Vault) Cat(files ...string) error {
	if len(files) == 0 {
		return fmt.Errorf("missing files")
	}
	for _, f := range files {
		if err := v.DecryptToStdout(f); err != nil {
			return fmt.Errorf("cat %s: %w", f, err)
		}
	}
	return nil
}

// If all is true, re-encrypts all *.age files tracked by Git.
// Init generates a new age key pair and writes it to AGE_SECRET_KEY_FILE
// (default: ~/.age/age.key). The public key is also written to a .pub file
// alongside it. Fails if the key file already exists.
func (v *Vault) Init(pq bool) error {
	keyPath := v.Config.SecretKeyFile
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("key file already exists: %s", keyPath)
	}

	var pub string
	if pq {
		id, err := GenerateHybridIdentityToFile(keyPath)
		if err != nil {
			return err
		}
		pub = id.Recipient().String()
	} else {
		id, err := GenerateIdentity(keyPath)
		if err != nil {
			return err
		}
		pub = id.Recipient().String()
	}

	ext := filepath.Ext(keyPath)
	pubPath := strings.TrimSuffix(keyPath, ext) + "." + v.Config.PubkeyExt
	if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0644); err != nil {
		return fmt.Errorf("write public key file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Generated new age key pair:\n\n")
	fmt.Fprintf(os.Stderr, "  Private key: %s\n", keyPath)
	fmt.Fprintf(os.Stderr, "  Public key:  %s\n\n", pubPath)
	fmt.Fprintf(os.Stderr, "Public key: %s\n", pub)
	return nil
}

func (v *Vault) Reencrypt(all bool, files ...string) error {
	if all {
		gitFiles, err := gitListAgeFiles()
		if err != nil {
			return err
		}
		if len(gitFiles) == 0 && len(files) == 0 {
			return fmt.Errorf("no tracked .age files found in Git")
		}
		files = append(gitFiles, files...)
	} else if len(files) == 0 {
		return fmt.Errorf("missing files. specify one or more files or use the --all option")
	}

	for _, f := range files {
		if err := v.reencryptFile(f); err != nil {
			return err
		}
		fmt.Printf("'%s' is reencrypted.\n", f)
	}
	return nil
}

// reencryptFile decrypts f in memory, re-encrypts it with current recipients,
// and writes the result back atomically.
func (v *Vault) reencryptFile(f string) error {
	recipients, err := v.GetRecipients(f)
	if err != nil {
		return err
	}

	// Decrypt to memory (secrets are small; this keeps the operation safe).
	var plain bytes.Buffer
	if err := v.decryptToWriter(&plain, f); err != nil {
		return fmt.Errorf("decrypt %s: %w", f, err)
	}

	// Encrypt to a temp file in the same directory, then rename atomically.
	dir := filepath.Dir(f)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".agevault.*.age.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if err := EncryptToFile(tmp, &plain, recipients); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("reencrypt %s: %w", f, err)
	}
	tmp.Close()

	if err := os.Rename(tmpName, f); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// Rotate re-encrypts files with a newly generated key and updates the recipients file.
// newKeyPath is the path for the new private key (created if it doesn't exist).
// If keepOldKey is true, the old key is kept alongside the new one in the recipients file.
// If all is true, all Git-tracked *.age files are rotated.
// If pq is true, a post-quantum hybrid ML-KEM-768+X25519 key is generated (requires all
// existing recipients to also be hybrid; can't mix with classic age1... recipients).
func (v *Vault) Rotate(newKeyPath string, keepOldKey, all, kmsOut, pq bool, files ...string) error {
	if all {
		gitFiles, err := gitListAgeFiles()
		if err != nil {
			return err
		}
		files = append(gitFiles, files...)
	}
	if len(files) == 0 {
		return fmt.Errorf("missing files. specify one or more files or use the --all option")
	}

	// Resolve current key type before generating the new key so we can inherit it.
	oldPub, err := v.GetPublicKey()
	if err != nil {
		return err
	}
	// Preserve the existing key type unless the caller explicitly requests PQ.
	effectivePQ := pq || strings.HasPrefix(oldPub, "age1pq1")

	var newPub string

	if kmsOut {
		// Generate a new key in memory and write the KMS-encrypted ciphertext to disk.
		provider, _, err := v.resolveKMS()
		if err != nil {
			return err
		}
		if provider == "" {
			return fmt.Errorf("--kms-out requires KMS to be configured (AGE_AWS_KMS_ENCRYPTED_KEY or AGE_GCP_KMS_ENCRYPTED_KEY)")
		}
		var keyStr, pubStr string
		if effectivePQ {
			id, err := age.GenerateHybridIdentity()
			if err != nil {
				return fmt.Errorf("generate identity: %w", err)
			}
			keyStr, pubStr = id.String(), id.Recipient().String()
		} else {
			id, err := age.GenerateX25519Identity()
			if err != nil {
				return fmt.Errorf("generate identity: %w", err)
			}
			keyStr, pubStr = id.String(), id.Recipient().String()
		}
		newPub = pubStr
		encryptor, err := v.newKMSEncryptor(provider)
		if err != nil {
			return err
		}
		ciphertext, err := encryptor.Encrypt(context.Background(), []byte(keyStr+"\n"))
		if err != nil {
			return fmt.Errorf("KMS encrypt new key: %w", err)
		}
		b64 := base64.StdEncoding.EncodeToString(ciphertext)
		if err := os.WriteFile(newKeyPath, []byte(b64+"\n"), 0600); err != nil {
			return fmt.Errorf("write %s: %w", newKeyPath, err)
		}
		fmt.Fprintf(os.Stderr, "[INFO] KMS-encrypted key written to '%s'\n", newKeyPath)
	} else {
		if _, err := os.Stat(newKeyPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[INFO] generating new key '%s'\n", newKeyPath)
			if effectivePQ {
				id, err := GenerateHybridIdentityToFile(newKeyPath)
				if err != nil {
					return err
				}
				newPub = id.Recipient().String()
			} else {
				id, err := GenerateIdentity(newKeyPath)
				if err != nil {
					return err
				}
				newPub = id.Recipient().String()
			}
		} else {
			// Key file already exists — use its type directly (ignore effectivePQ).
			newKeyData, err := os.ReadFile(newKeyPath)
			if err != nil {
				return fmt.Errorf("read new key file: %w", err)
			}
			newIds, err := age.ParseIdentities(strings.NewReader(string(newKeyData)))
			if err != nil {
				return fmt.Errorf("parse new key: %w", err)
			}
			if len(newIds) == 0 {
				return fmt.Errorf("no identities in new key file %s", newKeyPath)
			}
			newPub, err = identityPublicKey(newIds[0])
			if err != nil {
				return fmt.Errorf("new key %s: %w", newKeyPath, err)
			}
		}
	}

	if keepOldKey && strings.HasPrefix(oldPub, "age1pq1") != strings.HasPrefix(newPub, "age1pq1") {
		return fmt.Errorf("--keep-old-key cannot mix classic (age1) and post-quantum (age1pq1) recipients; omit --keep-old-key to do a clean migration")
	}

	for _, f := range files {
		rfPath, err := v.GetRecipientsFilePath(f)
		if err != nil {
			return err
		}
		if rfPath == "" {
			// AGE_RECIPIENTS is set (no file needed for encrypt/decrypt), but rotate
			// must update a recipients file. Resolve AGE_RECIPIENTS_FILE directly.
			rf := v.Config.RecipientsFile
			if !filepath.IsAbs(rf) && !strings.Contains(rf, string(filepath.Separator)) {
				rf = filepath.Join(filepath.Dir(f), rf)
			}
			if _, err := os.Stat(rf); os.IsNotExist(err) {
				return fmt.Errorf("rotate requires a recipients file on disk; set AGE_RECIPIENTS_FILE to a writable path")
			}
			rfPath = rf
		}

		// Update the recipients file.
		if err := updateRecipientsFile(rfPath, oldPub, newPub, keepOldKey); err != nil {
			return fmt.Errorf("update recipients file %s: %w", rfPath, err)
		}

		// Reencrypt using the old identity (still in v) and the updated recipients.
		if err := v.reencryptFile(f); err != nil {
			return err
		}
	}
	return nil
}

// updateRecipientsFile replaces oldPub with newPub in the recipients file.
// If keepOldKey is true, newPub is inserted after oldPub (unless already present).
func updateRecipientsFile(path, oldPub, newPub string, keepOldKey bool) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	contentStr := string(content)
	alreadyHasNew := strings.Contains(contentStr, newPub)

	var result strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(contentStr))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == oldPub {
			if keepOldKey {
				result.WriteString(line + "\n")
				if !alreadyHasNew {
					result.WriteString(newPub + "\n")
				}
			} else {
				result.WriteString(newPub + "\n")
			}
		} else {
			result.WriteString(line + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(result.String()), 0644)
}

// Edit opens an encrypted file in $EDITOR, then re-encrypts it on save if changed.
// If f ends in ".age", it decrypts it for editing. Otherwise it treats f as the
// plaintext name and f+".age" as the encrypted counterpart.
func (v *Vault) Edit(files ...string) error {
	if len(files) == 0 {
		return fmt.Errorf("missing files")
	}

	tmpDir, err := os.MkdirTemp("", ".agevault.*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, f := range files {
		if err := v.editFile(f, tmpDir); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) editFile(f, tmpDir string) error {
	base := filepath.Base(strings.TrimSuffix(f, ".age"))

	tmp, err := os.CreateTemp(tmpDir, "agevault-edit-*."+base)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	var encryptedFile string
	var encryptedFileExists bool

	if strings.HasSuffix(f, ".age") {
		encryptedFile = f
		if fi, statErr := os.Stat(encryptedFile); statErr == nil {
			if fi.Size() == 0 {
				// Empty .age file — treat as new (skip decryption).
				fmt.Fprintf(os.Stderr, "[INFO] '%s' is empty; opening blank file for editing.\n", encryptedFile)
			} else {
				encryptedFileExists = true
				if err := v.decryptToWriter(tmp, encryptedFile); err != nil {
					tmp.Close()
					return fmt.Errorf("decrypt: %w", err)
				}
			}
		}
		tmp.Close()
	} else {
		encryptedFile = f + ".age"
		if _, statErr := os.Stat(f); os.IsNotExist(statErr) {
			// Plaintext doesn't exist; try to edit the encrypted counterpart.
			if fi, statErr2 := os.Stat(encryptedFile); statErr2 == nil {
				if fi.Size() == 0 {
					// Empty .age file — treat as new (skip decryption).
					fmt.Fprintf(os.Stderr, "[INFO] '%s' is empty; opening blank file for editing.\n", encryptedFile)
				} else {
					encryptedFileExists = true
					if err := v.decryptToWriter(tmp, encryptedFile); err != nil {
						tmp.Close()
						return fmt.Errorf("decrypt: %w", err)
					}
				}
			}
			tmp.Close()
		} else {
			// Plaintext exists.
			if _, statErr2 := os.Stat(encryptedFile); statErr2 == nil {
				// Both exist – warn and skip.
				tmp.Close()
				fmt.Fprintf(os.Stderr, "[WARN] both '%s' and '%s' exist.\n", f, encryptedFile)
				fmt.Fprintf(os.Stderr, "[WARN] did you mean to edit '%s'?\n", encryptedFile)
				fmt.Fprintf(os.Stderr, "[WARN] consider using: agevault encrypt '%s'.\n", f)
				return nil
			}
			// Only plaintext exists; seed the temp file from it.
			src, err := os.Open(f)
			if err != nil {
				tmp.Close()
				return err
			}
			_, copyErr := io.Copy(tmp, src)
			src.Close()
			tmp.Close()
			if copyErr != nil {
				return copyErr
			}
		}
	}

	// Get recipients (using original f for directory resolution).
	recipients, err := v.GetRecipients(f)
	if err != nil {
		return err
	}

	// Hash the temp file before editing.
	origHash, err := hashFile(tmpName)
	if err != nil {
		return err
	}

	// Launch the editor.
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	parts := strings.Fields(editor)
	editorCmd := exec.Command(parts[0], append(parts[1:], tmpName)...)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	// Hash after editing.
	newHash, err := hashFile(tmpName)
	if err != nil {
		return err
	}

	info, _ := os.Stat(tmpName)
	isEmpty := info != nil && info.Size() == 0
	changed := !bytes.Equal(origHash, newHash) || (isEmpty && !encryptedFileExists)

	if !changed {
		return nil
	}

	// Re-encrypt to encryptedFile atomically.
	in, err := os.Open(tmpName)
	if err != nil {
		return err
	}
	defer in.Close()

	encDir := filepath.Dir(encryptedFile)
	if encDir == "" {
		encDir = "."
	}
	encTmp, err := os.CreateTemp(encDir, ".agevault.*.age.tmp")
	if err != nil {
		return fmt.Errorf("create enc temp: %w", err)
	}
	encTmpName := encTmp.Name()
	defer os.Remove(encTmpName)

	if err := EncryptToFile(encTmp, in, recipients); err != nil {
		encTmp.Close()
		return fmt.Errorf("encrypt: %w", err)
	}
	encTmp.Close()

	if err := os.Rename(encTmpName, encryptedFile); err != nil {
		return err
	}

	if !encryptedFileExists {
		fmt.Printf("'%s' is encrypted.\n", encryptedFile)
	} else {
		fmt.Printf("'%s' is updated.\n", encryptedFile)
	}
	return nil
}

// hashFile returns the SHA-256 digest of the named file's contents.
func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// gitListAgeFiles returns the absolute paths of all *.age files tracked by Git
// in the repository that contains the current working directory.
func gitListAgeFiles() ([]string, error) {
	if err := exec.Command("git", "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return nil, fmt.Errorf("cannot access Git repository")
	}

	rootOut, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return nil, fmt.Errorf("get git repo root: %w", err)
	}
	repoRoot := strings.TrimSpace(string(rootOut))

	listOut, err := exec.Command("git", "-C", repoRoot, "ls-files", "*.age").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(listOut)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, filepath.Join(repoRoot, line))
		}
	}
	return files, nil
}
