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
	"time"
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

// agentRequest is sent by a client immediately after connecting, then the
// client half-closes its write side (net.UnixConn.CloseWrite) to signal the
// request is complete. Secrets names which named secrets to merge into the
// response; an empty list requests the default (unnamed) secret.
type agentRequest struct {
	Secrets []string `json:"secrets,omitempty"`
}

// agentResponse is the server's reply: either a merged AgentBundle for the
// requested secrets, or an error (e.g. an unknown secret name).
type agentResponse struct {
	Bundle *AgentBundle `json:"bundle,omitempty"`
	Error  string       `json:"error,omitempty"`
}

// namedFile is one --env/--decrypt entry, optionally tagged with a secret
// name via a "name=" prefix (e.g. "db=db.env.age"). Entries without a "name="
// prefix belong to the default secret, named "".
type namedFile struct {
	name string
	path string
}

// parseNamedFiles splits each already comma-separated entry on its first "="
// to extract an optional secret name.
func parseNamedFiles(entries []string) []namedFile {
	files := make([]namedFile, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		name, path, ok := strings.Cut(e, "=")
		if !ok {
			files = append(files, namedFile{path: e})
			continue
		}
		files = append(files, namedFile{name: name, path: path})
	}
	return files
}

// displaySecretName renders the default (unnamed) secret as "(default)" for
// error messages, since "" on its own is easy to misread.
func displaySecretName(name string) string {
	if name == "" {
		return "(default)"
	}
	return name
}

// buildAgentBundles decrypts every envFiles/decryptFiles entry exactly once,
// grouping the results into named AgentBundles (see namedFile). Env entries
// sharing a name are merged into one deduped "KEY=VALUE" set; decrypt entries
// sharing a name are keyed by the basename of their decrypted (".age"-
// stripped) path, and two decrypt entries in the same secret that reduce to
// the same basename are rejected rather than letting one silently overwrite
// the other.
func (v *Vault) buildAgentBundles(envFiles, decryptFiles []string) (map[string]*AgentBundle, error) {
	envSpecs := parseNamedFiles(envFiles)
	decryptSpecs := parseNamedFiles(decryptFiles)
	if len(envSpecs) == 0 && len(decryptSpecs) == 0 {
		return nil, fmt.Errorf("no files provided")
	}

	bundles := make(map[string]*AgentBundle)
	bundle := func(name string) *AgentBundle {
		b, ok := bundles[name]
		if !ok {
			b = &AgentBundle{}
			bundles[name] = b
		}
		return b
	}

	for _, spec := range envSpecs {
		var buf bytes.Buffer
		if err := v.decryptToWriter(&buf, spec.path); err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", spec.path, err)
		}
		vars, err := parseEnvBytes(&buf)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", spec.path, err)
		}
		b := bundle(spec.name)
		b.Env = mergeEnv(b.Env, vars)
	}

	for _, spec := range decryptSpecs {
		var buf bytes.Buffer
		if err := v.decryptToWriter(&buf, spec.path); err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", spec.path, err)
		}
		b := bundle(spec.name)
		if b.Files == nil {
			b.Files = make(map[string][]byte)
		}
		name := filepath.Base(strings.TrimSuffix(spec.path, ".age"))
		if _, exists := b.Files[name]; exists {
			return nil, fmt.Errorf("duplicate decrypt file basename %q in secret %s (from %s): a secret can only serve one file per basename", name, displaySecretName(spec.name), spec.path)
		}
		b.Files[name] = buf.Bytes()
	}

	return bundles, nil
}

// availableSecretNames returns bundles' keys, sorted and rendered for
// display (see displaySecretName), for "unknown secret" error messages.
func availableSecretNames(bundles map[string]*AgentBundle) []string {
	names := make([]string, 0, len(bundles))
	for name := range bundles {
		names = append(names, displaySecretName(name))
	}
	sort.Strings(names)
	return names
}

// mergeNamedBundles merges the requested named bundles into one AgentBundle.
// An empty names list requests the default ("") bundle. Returns an error
// naming the secrets the agent actually serves if a requested name doesn't
// exist, or if two requested secrets both serve a file with the same
// basename (which one would silently win is undefined, so it's rejected).
func mergeNamedBundles(bundles map[string]*AgentBundle, names []string) (*AgentBundle, error) {
	if len(names) == 0 {
		names = []string{""}
	}

	merged := &AgentBundle{}
	for _, name := range names {
		b, ok := bundles[name]
		if !ok {
			return nil, fmt.Errorf("unknown secret %s; this agent serves: %s", displaySecretName(name), strings.Join(availableSecretNames(bundles), ", "))
		}
		merged.Env = mergeEnv(merged.Env, b.Env)
		for fname, data := range b.Files {
			if merged.Files == nil {
				merged.Files = make(map[string][]byte)
			}
			if _, exists := merged.Files[fname]; exists {
				return nil, fmt.Errorf("requested secrets %v both serve a file named %q", names, fname)
			}
			merged.Files[fname] = data
		}
	}
	return merged, nil
}

// RunAgent resolves the identity and decrypts envFiles/decryptFiles exactly
// once (this is where any KMS call happens), grouping the results into named
// secrets (see namedFile). It then serves merged AgentBundles as JSON to any
// client connecting to socketPath until ctx is cancelled — each client sends
// an agentRequest naming which secrets it wants merged into its response.
// The socket file is created with mode 0600 and removed on shutdown; a stale
// socket left behind by an unclean previous shutdown is removed before
// binding.
func (v *Vault) RunAgent(ctx context.Context, socketPath string, envFiles, decryptFiles []string) error {
	if socketPath == "" {
		return fmt.Errorf("socket path is required")
	}

	bundles, err := v.buildAgentBundles(envFiles, decryptFiles)
	if err != nil {
		return err
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
		go serveAgentConn(conn, bundles)
	}
}

// serveAgentConn reads one agentRequest from conn (until the client
// half-closes its write side or a deadline passes), merges the requested
// secrets, and writes back one agentResponse before closing the connection.
func serveAgentConn(conn net.Conn, bundles map[string]*AgentBundle) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reqData, err := io.ReadAll(conn)
	if err != nil {
		return
	}

	var req agentRequest
	if len(reqData) > 0 {
		if err := json.Unmarshal(reqData, &req); err != nil {
			writeAgentResponse(conn, agentResponse{Error: fmt.Sprintf("decode request: %v", err)})
			return
		}
	}

	merged, err := mergeNamedBundles(bundles, req.Secrets)
	if err != nil {
		writeAgentResponse(conn, agentResponse{Error: err.Error()})
		return
	}
	writeAgentResponse(conn, agentResponse{Bundle: merged})
}

func writeAgentResponse(conn net.Conn, resp agentResponse) {
	payload, err := json.Marshal(resp)
	if err != nil {
		payload, _ = json.Marshal(agentResponse{Error: fmt.Sprintf("marshal response: %v", err)})
	}
	_, _ = conn.Write(payload)
}

// DialAgentBundle connects to an agevault agent's socket, requests the named
// secrets, and returns them merged into one AgentBundle. An empty/nil names
// list requests the default (unnamed) secret.
func DialAgentBundle(socketPath string, names []string) (*AgentBundle, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to agent socket %s: %w", socketPath, err)
	}
	defer conn.Close()

	reqPayload, err := json.Marshal(agentRequest{Secrets: names})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	if _, err := conn.Write(reqPayload); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		if err := uc.CloseWrite(); err != nil {
			return nil, fmt.Errorf("close write side: %w", err)
		}
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read from agent socket: %w", err)
	}

	var resp agentResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode agent response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("agent: %s", resp.Error)
	}
	if resp.Bundle == nil {
		return &AgentBundle{}, nil
	}
	return resp.Bundle, nil
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

// AgentRun connects to an agevault agent's socket, requests secretNames (the
// default/unnamed secret if empty), applies the returned bundle (writing any
// files to the current directory and merging env vars), then execs command,
// replacing the current process. Unlike Run, this needs no local identity,
// recipients, or KMS access — only the agent does.
func (v *Vault) AgentRun(socketPath string, secretNames, command []string) error {
	if socketPath == "" {
		return fmt.Errorf("socket path is required (use --socket or AGE_AGENT_SOCKET)")
	}
	if len(command) == 0 {
		return fmt.Errorf("no command specified. Use '--' to separate the socket from the command")
	}

	bundle, err := DialAgentBundle(socketPath, secretNames)
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
