// Package keyagent is the agevault key agent: the server behind the
// agevault-agent binary and the client that decrypts through it. It depends
// only on filippo.io/age, so a program that just wants to decrypt with keys an
// agent already holds can import it without the rest of agevault.
package keyagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"filippo.io/age"
)

// The key agent (the agevault-agent binary) is the ssh-agent counterpart for
// age identities: it holds unlocked private keys in memory and performs the
// private-key step of decryption on behalf of clients, so a
// passphrase-protected key file is unlocked once rather than on every
// command. Private keys go in (add) but never come back out: the only things
// a client can get are public keys (list) and the per-file key of an age file
// it presents the header stanzas of (unwrap).
//
// This is unrelated to the 'agevault agent' sidecar, which serves
// already-decrypted secrets and holds no key.

const (
	opAdd    = "add"
	opList   = "list"
	opClear  = "clear"
	opUnwrap = "unwrap"

	codeNoKeys  = "no_keys"
	codeNoMatch = "no_match"

	maxRequest = 1 << 20
	ioTimeout  = 10 * time.Second
)

// request is the single JSON request a client sends per connection
// before half-closing its write side.
type request struct {
	Op string `json:"op"`

	// add: key file content in age-keygen format, an optional lifetime after
	// which the agent forgets the key (0 = until the agent exits), and where
	// it came from: the key file's path (a label for list) and the
	// fingerprint of its on-disk bytes (see Fingerprint).
	Key             string `json:"key,omitempty"`
	LifetimeSeconds int64  `json:"lifetime_seconds,omitempty"`
	Source          string `json:"source,omitempty"`
	Fingerprint     string `json:"fingerprint,omitempty"`

	// unwrap: the recipient stanzas from an age file header.
	Stanzas []*age.Stanza `json:"stanzas,omitempty"`
}

type response struct {
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`

	Keys    []Key    `json:"keys,omitempty"`     // list
	Added   []string `json:"added,omitempty"`    // add: public keys
	FileKey []byte   `json:"file_key,omitempty"` // unwrap
}

// Key describes one key held by a key agent.
type Key struct {
	PublicKey string `json:"public_key"`
	// Source is the resolved path of the key file the key was last added
	// from; empty if the client that added it did not say. It is a label
	// only: a path says where a key came from, not what is at that path now.
	Source string `json:"source,omitempty"`
	// Fingerprints identify the key files this key was added from, by
	// content (see Fingerprint).
	Fingerprints []string `json:"fingerprints,omitempty"`
	// Expires is when the agent will forget the key; nil means never.
	Expires *time.Time `json:"expires,omitempty"`
}

type heldKey struct {
	pub     string
	source  string
	prints  []string
	id      age.Identity
	expires time.Time // zero = never
}

// Agent holds unlocked age identities in memory and serves them over a
// Unix socket. The zero value is an empty agent, ready to Serve.
type Agent struct {
	mu   sync.Mutex
	keys []*heldKey
}

// Serve listens on socketPath (mode 0600) until ctx is cancelled, removing
// the socket on shutdown. A stale socket from an unclean shutdown is
// replaced; a socket another agent is still answering on is an error.
func (a *Agent) Serve(ctx context.Context, socketPath string) error {
	if socketPath == "" {
		return fmt.Errorf("socket path is required (use --socket or AGE_KEY_AGENT_SOCKET)")
	}
	hardenProcess()

	if _, err := os.Stat(socketPath); err == nil {
		if conn, err := net.Dial("unix", socketPath); err == nil {
			conn.Close()
			return fmt.Errorf("another agent is already listening on %s", socketPath)
		}
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
	slog.Info("key agent listening", "socket", socketPath)

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
		go a.serveConn(conn)
	}
}

func (a *Agent) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))

	data, err := io.ReadAll(io.LimitReader(conn, maxRequest))
	if err != nil {
		return
	}
	// An empty request is a bare connect-and-close (liveness probe).
	if len(data) == 0 {
		return
	}

	var req request
	var resp response
	if err := json.Unmarshal(data, &req); err != nil {
		resp.Error = fmt.Sprintf("decode request: %v", err)
	} else {
		resp = a.handle(&req)
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		payload, _ = json.Marshal(response{Error: fmt.Sprintf("encode response: %v", err)})
	}
	_, _ = conn.Write(payload)
}

func (a *Agent) handle(req *request) response {
	switch req.Op {
	case opAdd:
		added, err := a.add(req.Key, req.Source, req.Fingerprint, time.Duration(req.LifetimeSeconds)*time.Second)
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{Added: added}
	case opList:
		return response{Keys: a.list()}
	case opClear:
		n := a.clear()
		slog.Info("keys removed", "count", n)
		return response{}
	case opUnwrap:
		return a.unwrap(req.Stanzas)
	default:
		return response{Error: fmt.Sprintf("unknown operation %q", req.Op)}
	}
}

// purgeLocked drops expired keys. a.mu must be held.
func (a *Agent) purgeLocked() {
	now := time.Now()
	kept := a.keys[:0]
	for _, k := range a.keys {
		if k.expires.IsZero() || now.Before(k.expires) {
			kept = append(kept, k)
		} else {
			slog.Info("key expired", "public_key", k.pub)
		}
	}
	for i := len(kept); i < len(a.keys); i++ {
		a.keys[i] = nil
	}
	a.keys = kept
}

func (a *Agent) add(keyData, source, fingerprint string, lifetime time.Duration) ([]string, error) {
	if lifetime < 0 {
		return nil, fmt.Errorf("lifetime must not be negative")
	}
	ids, err := age.ParseIdentities(bytes.NewReader([]byte(keyData)))
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities in key")
	}

	var expires time.Time
	if lifetime > 0 {
		expires = time.Now().Add(lifetime)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.purgeLocked()

	var added []string
	for _, id := range ids {
		pub, err := publicKeyOf(id)
		if err != nil {
			return nil, err
		}
		entry := &heldKey{pub: pub, source: source, id: id, expires: expires}
		if fingerprint != "" {
			entry.prints = []string{fingerprint}
		}
		replaced := false
		for i, k := range a.keys {
			if k.pub == pub {
				// Re-adding refreshes the lifetime and source. Fingerprints
				// accumulate: each one still names a file holding this key.
				for _, fp := range k.prints {
					if !slices.Contains(entry.prints, fp) {
						entry.prints = append(entry.prints, fp)
					}
				}
				a.keys[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			a.keys = append(a.keys, entry)
		}
		added = append(added, pub)
		slog.Info("key added", "public_key", pub, "source", source, "lifetime", lifetime.String())
	}

	if lifetime > 0 {
		// Forget the key when it expires even if no request arrives.
		time.AfterFunc(lifetime+time.Millisecond, func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.purgeLocked()
		})
	}
	return added, nil
}

func (a *Agent) list() []Key {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purgeLocked()

	keys := make([]Key, 0, len(a.keys))
	for _, k := range a.keys {
		entry := Key{PublicKey: k.pub, Source: k.source, Fingerprints: slices.Clone(k.prints)}
		if !k.expires.IsZero() {
			exp := k.expires
			entry.Expires = &exp
		}
		keys = append(keys, entry)
	}
	return keys
}

func (a *Agent) clear() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.keys)
	for i := range a.keys {
		a.keys[i] = nil
	}
	a.keys = nil
	return n
}

// unwrap performs the private-key step of age decryption: given a file
// header's recipient stanzas, it returns that file's own file key if any held
// identity is a recipient.
func (a *Agent) unwrap(stanzas []*age.Stanza) response {
	a.mu.Lock()
	a.purgeLocked()
	ids := make([]age.Identity, len(a.keys))
	for i, k := range a.keys {
		ids[i] = k.id
	}
	a.mu.Unlock()

	if len(ids) == 0 {
		return response{Code: codeNoKeys, Error: "the agent has no keys"}
	}
	for _, id := range ids {
		fileKey, err := id.Unwrap(stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{FileKey: fileKey}
	}
	return response{Code: codeNoMatch, Error: "no key in the agent matches this file"}
}

// roundTrip sends one request to the agent at socketPath and returns
// its response. Agent-reported errors are left in resp.Error for the caller.
func roundTrip(socketPath string, req request) (*response, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to key agent %s: %w", socketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		if err := uc.CloseWrite(); err != nil {
			return nil, fmt.Errorf("close write side: %w", err)
		}
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read from key agent: %w", err)
	}
	var resp response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode key agent response: %w", err)
	}
	return &resp, nil
}

func call(socketPath string, req request) (*response, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("socket path is required (use --socket or AGE_KEY_AGENT_SOCKET)")
	}
	resp, err := roundTrip(socketPath, req)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("key agent: %s", resp.Error)
	}
	return resp, nil
}

// Add hands plaintext key file content (age-keygen format) to the key
// agent at socketPath, returning the public keys it now holds for it. A
// positive lifetime makes the agent forget the key after that long.
//
// The key is recorded without a source key file, so the agent only ever
// decrypts with it: it is never taken for the key of a key file (see
// Identity). AddFromFile records the file the key came from.
func Add(socketPath string, keyData []byte, lifetime time.Duration) ([]string, error) {
	return sendAdd(socketPath, request{Key: string(keyData)}, lifetime)
}

// AddFromFile is Add for a key read from a key file: source is the file's
// path (a label for List) and fingerprint the Fingerprint of its on-disk
// bytes, by which clients later recognise the key as that file's.
func AddFromFile(socketPath string, keyData []byte, source, fingerprint string, lifetime time.Duration) ([]string, error) {
	return sendAdd(socketPath, request{Key: string(keyData), Source: source, Fingerprint: fingerprint}, lifetime)
}

func sendAdd(socketPath string, req request, lifetime time.Duration) ([]string, error) {
	req.Op = opAdd
	req.LifetimeSeconds = int64(lifetime / time.Second)
	resp, err := call(socketPath, req)
	if err != nil {
		return nil, err
	}
	return resp.Added, nil
}

// List returns the keys held by the key agent at socketPath, in the
// order they were added.
func List(socketPath string) ([]Key, error) {
	resp, err := call(socketPath, request{Op: opList})
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// Clear makes the key agent at socketPath forget all its keys.
func Clear(socketPath string) error {
	_, err := call(socketPath, request{Op: opClear})
	return err
}

// SocketEnv is the environment variable naming the key agent's socket.
const SocketEnv = "AGE_KEY_AGENT_SOCKET"

// Fingerprint identifies a key file by content: the SHA-256 of its bytes as
// they are on disk, i.e. of the ciphertext for a passphrase-protected file. It
// can therefore be computed without the passphrase, which is how a client
// recognises the key of its (locked) key file among the agent's keys. Unlike
// a path it cannot go stale: a replaced file has another fingerprint.
// Changing a file's passphrase changes it too, so the key has to be re-added.
func Fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func publicKeyOf(id age.Identity) (string, error) {
	switch id := id.(type) {
	case *age.X25519Identity:
		return id.Recipient().String(), nil
	case *age.HybridIdentity:
		return id.Recipient().String(), nil
	default:
		return "", fmt.Errorf("unsupported identity type %T", id)
	}
}

// Identity is an age.Identity that decrypts through a key agent: Unwrap
// forwards the header stanzas to the agent, which tries every key it holds.
// The private keys never leave the agent.
type Identity struct {
	// SocketPath is the agent's socket.
	SocketPath string

	// PublicKey is the public key of the caller's key file, set only when
	// the agent verifiably holds that very key: one of its keys was added
	// from a file with the same content. It is never just "a key the agent
	// has" — who the caller is stays the key file's call.
	PublicKey string

	// Fallback, if set, supplies the key file's identity for a file none of
	// the agent's keys can decrypt. It is not consulted when PublicKey is
	// set, since the agent then already tried that key. Returning a nil
	// identity and a nil error means there is no key file to try.
	Fallback func() (age.Identity, error)
}

// NewIdentity returns an Identity backed by the agent at socketPath, or nil
// if socketPath is empty, the agent is not reachable, or it holds no keys —
// in which case the caller falls back to the key file, the same way ssh falls
// back from an empty ssh-agent to the key files. keyFile is the caller's own
// key file; it is only read to see whether the agent holds its key.
func NewIdentity(socketPath, keyFile string) *Identity {
	if socketPath == "" {
		return nil
	}
	keys, err := List(socketPath)
	if err != nil || len(keys) == 0 {
		return nil
	}
	id := &Identity{SocketPath: socketPath}
	if data, err := os.ReadFile(keyFile); err == nil {
		fp := Fingerprint(data)
		for _, k := range keys {
			if slices.Contains(k.Fingerprints, fp) {
				id.PublicKey = k.PublicKey
				break
			}
		}
	}
	return id
}

// Unwrap implements age.Identity.
func (i *Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	resp, err := roundTrip(i.SocketPath, request{Op: opUnwrap, Stanzas: stanzas})
	if err != nil {
		return nil, err
	}
	switch {
	case resp.Code == codeNoMatch || resp.Code == codeNoKeys:
		return i.unwrapWithFallback(stanzas)
	case resp.Error != "":
		return nil, fmt.Errorf("key agent: %s", resp.Error)
	}
	return resp.FileKey, nil
}

func (i *Identity) unwrapWithFallback(stanzas []*age.Stanza) ([]byte, error) {
	if i.PublicKey != "" || i.Fallback == nil {
		return nil, age.ErrIncorrectIdentity
	}
	id, err := i.Fallback()
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, age.ErrIncorrectIdentity
	}
	return id.Unwrap(stanzas)
}
