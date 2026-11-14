package agevault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
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
// This is unrelated to the 'agevault agent' sidecar in agent.go, which serves
// already-decrypted secrets and holds no key.

const (
	keyAgentOpAdd    = "add"
	keyAgentOpList   = "list"
	keyAgentOpClear  = "clear"
	keyAgentOpUnwrap = "unwrap"

	keyAgentCodeNoKeys  = "no_keys"
	keyAgentCodeNoMatch = "no_match"

	keyAgentMaxRequest = 1 << 20
	keyAgentIOTimeout  = 10 * time.Second
)

// keyAgentRequest is the single JSON request a client sends per connection
// before half-closing its write side.
type keyAgentRequest struct {
	Op string `json:"op"`

	// add: key file content in age-keygen format, and an optional lifetime
	// after which the agent forgets the key (0 = until the agent exits).
	Key             string `json:"key,omitempty"`
	LifetimeSeconds int64  `json:"lifetime_seconds,omitempty"`

	// unwrap: the recipient stanzas from an age file header.
	Stanzas []*age.Stanza `json:"stanzas,omitempty"`
}

type keyAgentResponse struct {
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`

	Keys    []KeyAgentKey `json:"keys,omitempty"`     // list
	Added   []string      `json:"added,omitempty"`    // add: public keys
	FileKey []byte        `json:"file_key,omitempty"` // unwrap
}

// KeyAgentKey describes one key held by a key agent.
type KeyAgentKey struct {
	PublicKey string `json:"public_key"`
	// Expires is when the agent will forget the key; nil means never.
	Expires *time.Time `json:"expires,omitempty"`
}

type keyAgentEntry struct {
	pub     string
	id      age.Identity
	expires time.Time // zero = never
}

// KeyAgent holds unlocked age identities in memory and serves them over a
// Unix socket. The zero value is an empty agent, ready to Serve.
type KeyAgent struct {
	mu   sync.Mutex
	keys []*keyAgentEntry
}

// Serve listens on socketPath (mode 0600) until ctx is cancelled, removing
// the socket on shutdown. A stale socket from an unclean shutdown is
// replaced; a socket another agent is still answering on is an error.
func (a *KeyAgent) Serve(ctx context.Context, socketPath string) error {
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

func (a *KeyAgent) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(keyAgentIOTimeout))

	data, err := io.ReadAll(io.LimitReader(conn, keyAgentMaxRequest))
	if err != nil {
		return
	}
	// An empty request is a bare connect-and-close (liveness probe).
	if len(data) == 0 {
		return
	}

	var req keyAgentRequest
	var resp keyAgentResponse
	if err := json.Unmarshal(data, &req); err != nil {
		resp.Error = fmt.Sprintf("decode request: %v", err)
	} else {
		resp = a.handle(&req)
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		payload, _ = json.Marshal(keyAgentResponse{Error: fmt.Sprintf("encode response: %v", err)})
	}
	_, _ = conn.Write(payload)
}

func (a *KeyAgent) handle(req *keyAgentRequest) keyAgentResponse {
	switch req.Op {
	case keyAgentOpAdd:
		added, err := a.add(req.Key, time.Duration(req.LifetimeSeconds)*time.Second)
		if err != nil {
			return keyAgentResponse{Error: err.Error()}
		}
		return keyAgentResponse{Added: added}
	case keyAgentOpList:
		return keyAgentResponse{Keys: a.list()}
	case keyAgentOpClear:
		n := a.clear()
		slog.Info("keys removed", "count", n)
		return keyAgentResponse{}
	case keyAgentOpUnwrap:
		return a.unwrap(req.Stanzas)
	default:
		return keyAgentResponse{Error: fmt.Sprintf("unknown operation %q", req.Op)}
	}
}

// purgeLocked drops expired keys. a.mu must be held.
func (a *KeyAgent) purgeLocked() {
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

func (a *KeyAgent) add(keyData string, lifetime time.Duration) ([]string, error) {
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
		pub, err := identityPublicKey(id)
		if err != nil {
			return nil, err
		}
		entry := &keyAgentEntry{pub: pub, id: id, expires: expires}
		replaced := false
		for i, k := range a.keys {
			if k.pub == pub {
				a.keys[i] = entry // re-adding refreshes the lifetime
				replaced = true
				break
			}
		}
		if !replaced {
			a.keys = append(a.keys, entry)
		}
		added = append(added, pub)
		slog.Info("key added", "public_key", pub, "lifetime", lifetime.String())
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

func (a *KeyAgent) list() []KeyAgentKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purgeLocked()

	keys := make([]KeyAgentKey, 0, len(a.keys))
	for _, k := range a.keys {
		entry := KeyAgentKey{PublicKey: k.pub}
		if !k.expires.IsZero() {
			exp := k.expires
			entry.Expires = &exp
		}
		keys = append(keys, entry)
	}
	return keys
}

func (a *KeyAgent) clear() int {
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
func (a *KeyAgent) unwrap(stanzas []*age.Stanza) keyAgentResponse {
	a.mu.Lock()
	a.purgeLocked()
	ids := make([]age.Identity, len(a.keys))
	for i, k := range a.keys {
		ids[i] = k.id
	}
	a.mu.Unlock()

	if len(ids) == 0 {
		return keyAgentResponse{Code: keyAgentCodeNoKeys, Error: "the agent has no keys"}
	}
	for _, id := range ids {
		fileKey, err := id.Unwrap(stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return keyAgentResponse{Error: err.Error()}
		}
		return keyAgentResponse{FileKey: fileKey}
	}
	return keyAgentResponse{Code: keyAgentCodeNoMatch, Error: "no key in the agent matches this file"}
}

// keyAgentRoundTrip sends one request to the agent at socketPath and returns
// its response. Agent-reported errors are left in resp.Error for the caller.
func keyAgentRoundTrip(socketPath string, req keyAgentRequest) (*keyAgentResponse, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to key agent %s: %w", socketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(keyAgentIOTimeout))

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
	var resp keyAgentResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode key agent response: %w", err)
	}
	return &resp, nil
}

func keyAgentCall(socketPath string, req keyAgentRequest) (*keyAgentResponse, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("socket path is required (use --socket or AGE_KEY_AGENT_SOCKET)")
	}
	resp, err := keyAgentRoundTrip(socketPath, req)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("key agent: %s", resp.Error)
	}
	return resp, nil
}

// KeyAgentAdd hands plaintext key file content (age-keygen format) to the key
// agent at socketPath, returning the public keys it now holds for it. A
// positive lifetime makes the agent forget the key after that long.
func KeyAgentAdd(socketPath string, keyData []byte, lifetime time.Duration) ([]string, error) {
	resp, err := keyAgentCall(socketPath, keyAgentRequest{
		Op:              keyAgentOpAdd,
		Key:             string(keyData),
		LifetimeSeconds: int64(lifetime / time.Second),
	})
	if err != nil {
		return nil, err
	}
	return resp.Added, nil
}

// KeyAgentList returns the keys held by the key agent at socketPath, in the
// order they were added.
func KeyAgentList(socketPath string) ([]KeyAgentKey, error) {
	resp, err := keyAgentCall(socketPath, keyAgentRequest{Op: keyAgentOpList})
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// KeyAgentClear makes the key agent at socketPath forget all its keys.
func KeyAgentClear(socketPath string) error {
	_, err := keyAgentCall(socketPath, keyAgentRequest{Op: keyAgentOpClear})
	return err
}

// AddKeyToAgent unlocks keyFile (prompting for its passphrase if it is
// protected) and adds it to the key agent at socketPath.
func (v *Vault) AddKeyToAgent(socketPath, keyFile string, lifetime time.Duration) ([]string, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("socket path is required (use --socket or AGE_KEY_AGENT_SOCKET)")
	}
	// Fail before prompting if there is no agent to hand the key to.
	if _, err := KeyAgentList(socketPath); err != nil {
		return nil, err
	}
	plain, _, err := v.readKeyFile(keyFile)
	if err != nil {
		return nil, err
	}
	return KeyAgentAdd(socketPath, plain, lifetime)
}

// keyAgentIdentity is an age.Identity backed by a key agent: Unwrap forwards
// the header stanzas to the agent, which tries every key it holds. pub is the
// public key of the agent's first key, used where a command needs "my" public
// key (pubkey, rotate, --self).
type keyAgentIdentity struct {
	socketPath string
	pub        string
}

func (i *keyAgentIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	resp, err := keyAgentRoundTrip(i.socketPath, keyAgentRequest{Op: keyAgentOpUnwrap, Stanzas: stanzas})
	if err != nil {
		return nil, err
	}
	switch {
	case resp.Code == keyAgentCodeNoMatch:
		return nil, age.ErrIncorrectIdentity
	case resp.Error != "":
		return nil, fmt.Errorf("key agent: %s", resp.Error)
	}
	return resp.FileKey, nil
}

// keyAgentIdentity returns an identity backed by the configured key agent, or
// nil if no agent is configured, it is not reachable, or it holds no keys —
// in which case the caller falls back to the key file, the same way ssh
// falls back from an empty ssh-agent to the key files.
func (v *Vault) keyAgentIdentity() age.Identity {
	socketPath := v.Config.KeyAgentSocket
	if socketPath == "" {
		return nil
	}
	keys, err := KeyAgentList(socketPath)
	if err != nil || len(keys) == 0 {
		return nil
	}
	return &keyAgentIdentity{socketPath: socketPath, pub: keys[0].PublicKey}
}
