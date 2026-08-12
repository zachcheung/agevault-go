package agevault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// AgentBundle is the plaintext payload an agevault agent serves to clients over
// its Unix socket. Env holds already-merged "KEY=VALUE" lines; Files maps a
// location-independent identifier (the basename of the decrypted path) to
// plaintext content, since the agent and its clients are typically different
// filesystems/containers and the agent's own path has no meaning to a client.
type AgentBundle struct {
	Env   []string          `json:"env,omitempty"`
	Files map[string][]byte `json:"files,omitempty"`
}

// buildAgentBundle decrypts envFiles and decryptFiles exactly once, merging env
// files into a deduped set of "KEY=VALUE" lines and keying decrypt files by the
// basename of their decrypted (".age"-stripped) path.
func (v *Vault) buildAgentBundle(envFiles, decryptFiles []string) (*AgentBundle, error) {
	if len(envFiles) == 0 && len(decryptFiles) == 0 {
		return nil, fmt.Errorf("no files provided")
	}

	bundle := &AgentBundle{}

	for _, f := range envFiles {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		var buf bytes.Buffer
		if err := v.decryptToWriter(&buf, f); err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", f, err)
		}
		vars, err := parseEnvBytes(&buf)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		bundle.Env = mergeEnv(bundle.Env, vars)
	}

	for _, f := range decryptFiles {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		var buf bytes.Buffer
		if err := v.decryptToWriter(&buf, f); err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", f, err)
		}
		if bundle.Files == nil {
			bundle.Files = make(map[string][]byte)
		}
		name := filepath.Base(strings.TrimSuffix(f, ".age"))
		if _, exists := bundle.Files[name]; exists {
			return nil, fmt.Errorf("duplicate decrypt file basename %q (from %s): agent can only serve one file per basename", name, f)
		}
		bundle.Files[name] = buf.Bytes()
	}

	return bundle, nil
}

// RunAgent resolves the identity and decrypts envFiles/decryptFiles exactly once
// (this is where any KMS call happens), then serves the resulting AgentBundle as
// JSON to any client connecting to socketPath until ctx is cancelled. The socket
// file is created with mode 0600 and removed on shutdown; a stale socket left
// behind by an unclean previous shutdown is removed before binding.
func (v *Vault) RunAgent(ctx context.Context, socketPath string, envFiles, decryptFiles []string) error {
	if socketPath == "" {
		return fmt.Errorf("socket path is required")
	}

	bundle, err := v.buildAgentBundle(envFiles, decryptFiles)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}

	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale socket %s: %w", socketPath, err)
		}
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer os.Remove(socketPath)

	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return fmt.Errorf("chmod %s: %w", socketPath, err)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go func() {
			defer conn.Close()
			_, _ = conn.Write(payload)
		}()
	}
}

// DialAgentBundle connects to an agevault agent's socket and reads its AgentBundle.
func DialAgentBundle(socketPath string) (*AgentBundle, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to agent socket %s: %w", socketPath, err)
	}
	defer conn.Close()

	data, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read from agent socket: %w", err)
	}

	var bundle AgentBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("decode agent bundle: %w", err)
	}
	return &bundle, nil
}

// ApplyAgentBundle writes bundle.Files into destDir (default ".") atomically and
// returns baseEnv merged with bundle.Env, ready to be passed to syscall.Exec.
func ApplyAgentBundle(bundle *AgentBundle, baseEnv []string, destDir string) ([]string, error) {
	if destDir == "" {
		destDir = "."
	}

	names := make([]string, 0, len(bundle.Files))
	for name := range bundle.Files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if err := writeFileAtomic(filepath.Join(destDir, name), bundle.Files[name]); err != nil {
			return nil, fmt.Errorf("write %s: %w", name, err)
		}
	}

	return mergeEnv(baseEnv, bundle.Env), nil
}

// AgentRun connects to an agevault agent's socket, applies the returned bundle
// (writing any files to the current directory and merging env vars), then execs
// command, replacing the current process. Unlike Run, this needs no local
// identity, recipients, or KMS access — only the agent does.
func (v *Vault) AgentRun(socketPath string, command []string) error {
	if socketPath == "" {
		return fmt.Errorf("socket path is required (use --socket or AGE_AGENT_SOCKET)")
	}
	if len(command) == 0 {
		return fmt.Errorf("no command specified. Use '--' to separate the socket from the command")
	}

	bundle, err := DialAgentBundle(socketPath)
	if err != nil {
		return err
	}

	environ, err := ApplyAgentBundle(bundle, os.Environ(), ".")
	if err != nil {
		return err
	}

	cmdPath, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("command not found: %s: %w", command[0], err)
	}
	return syscall.Exec(cmdPath, command, environ)
}

// writeFileAtomic writes data to dst via a temp file in the same directory
// followed by a rename, so a partial write never leaves dst in a bad state.
func writeFileAtomic(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".agevault.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()

	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
