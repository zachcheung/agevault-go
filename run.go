package agevault

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Run decrypts env files and/or decrypt files, then execs the given command,
// replacing the current process. envFiles are decrypted and their KEY=VALUE
// pairs are merged into the environment. decryptFiles are decrypted to their
// original paths (removing .age suffix) without loading as env vars.
func (v *Vault) Run(envFiles, decryptFiles, command []string) error {
	if len(envFiles) == 0 && len(decryptFiles) == 0 {
		return fmt.Errorf("no files provided")
	}
	if len(command) == 0 {
		return fmt.Errorf("no command specified. Use '--' to separate files from command")
	}

	tmpDir, err := os.MkdirTemp("", ".agevault.*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	// Note: we call os.RemoveAll(tmpDir) explicitly before syscall.Exec
	// so defer won't miss it due to process replacement.

	// Build environment from current env + decrypted env files.
	environ := os.Environ()
	for _, f := range envFiles {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		vars, err := v.decryptEnvFile(f, tmpDir)
		if err != nil {
			os.RemoveAll(tmpDir)
			return fmt.Errorf("load env %s: %w", f, err)
		}
		environ = mergeEnv(environ, vars)
	}

	// Decrypt files to their original locations.
	if len(decryptFiles) > 0 {
		if err := v.Decrypt(decryptFiles...); err != nil {
			os.RemoveAll(tmpDir)
			return fmt.Errorf("decrypt files: %w", err)
		}
	}

	os.RemoveAll(tmpDir)

	// Exec the command (replaces the current process).
	cmdPath, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("command not found: %s: %w", command[0], err)
	}
	return syscall.Exec(cmdPath, command, environ)
}

// decryptEnvFile decrypts a .age env file to a temp file and returns its KEY=VALUE pairs.
func (v *Vault) decryptEnvFile(f, tmpDir string) ([]string, error) {
	tmp, err := os.CreateTemp(tmpDir, "env.*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()

	if err := v.decryptToWriter(tmp, f); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()

	return parseEnvFile(tmpName)
}

// parseEnvFile reads KEY=VALUE pairs from a file (ignoring blank lines and comments).
func parseEnvFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseEnvBytes(f)
}

// parseEnvBytes reads KEY=VALUE pairs from r (ignoring blank lines and comments).
func parseEnvBytes(r io.Reader) ([]string, error) {
	var vars []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "=") {
			continue
		}
		vars = append(vars, line)
	}
	return vars, scanner.Err()
}

// mergeEnv merges additions into base, overwriting existing keys.
func mergeEnv(base, additions []string) []string {
	index := make(map[string]int, len(base))
	result := make([]string, len(base))
	copy(result, base)

	for i, e := range result {
		if eq := strings.IndexByte(e, '='); eq > 0 {
			index[e[:eq]] = i
		}
	}

	for _, e := range additions {
		eq := strings.IndexByte(e, '=')
		if eq <= 0 {
			continue
		}
		key := e[:eq]
		if idx, ok := index[key]; ok {
			result[idx] = e
		} else {
			index[key] = len(result)
			result = append(result, e)
		}
	}
	return result
}

// ParseRunArgs parses raw arguments for the run subcommand.
// Handles --env, --decrypt, --, and bare positional args (backwards-compat env files).
func ParseRunArgs(args []string) (envFiles, decryptFiles, command []string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--env":
			i++
			if i >= len(args) {
				err = fmt.Errorf("missing files after --env")
				return
			}
			for _, f := range strings.Split(args[i], ",") {
				if f = strings.TrimSpace(f); f != "" {
					envFiles = append(envFiles, f)
				}
			}
		case "--decrypt":
			i++
			if i >= len(args) {
				err = fmt.Errorf("missing files after --decrypt")
				return
			}
			for _, f := range strings.Split(args[i], ",") {
				if f = strings.TrimSpace(f); f != "" {
					decryptFiles = append(decryptFiles, f)
				}
			}
		case "--":
			command = args[i+1:]
			return
		default:
			if strings.HasPrefix(args[i], "-") {
				err = fmt.Errorf("unknown flag: %s", args[i])
				return
			}
			// Backwards compatibility: bare positional args are env files.
			envFiles = append(envFiles, args[i])
		}
	}
	return
}
