package agevault

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/zachcheung/agevault-go/keyagent"
)

// The key agent itself (server, protocol and the decrypting client) lives in
// the keyagent package. What stays here is the part that needs a Vault:
// unlocking a key file to hand it to the agent, and falling back to the key
// file for what the agent cannot do.

// AddKeyToAgent unlocks keyFile (prompting for its passphrase if it is
// protected) and adds it to the key agent at socketPath.
func (v *Vault) AddKeyToAgent(socketPath, keyFile string, lifetime time.Duration) ([]string, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("socket path is required (use --socket or AGE_KEY_AGENT_SOCKET)")
	}
	// Fail before prompting if there is no agent to hand the key to.
	if _, err := keyagent.List(socketPath); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("open key file %s: %w", keyFile, err)
	}
	// Fingerprint the very bytes that get unlocked, so the fingerprint can
	// never describe a different file than the key came from.
	plain, _, err := v.unlockKeyData(keyFile, data)
	if err != nil {
		return nil, err
	}
	return keyagent.AddFromFile(socketPath, plain, resolveKeyPath(keyFile), keyagent.Fingerprint(data), lifetime)
}

// resolveKeyPath returns path as an absolute path with symlinks resolved. A
// path that cannot be resolved is returned absolute but otherwise as-is.
func resolveKeyPath(path string) string {
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// keyAgentIdentity is the identity used while a key agent holds keys.
//
// Decryption is the agent's job: Unwrap forwards the header stanzas to the
// agent, which tries every key it holds, and only if none fits falls back to
// the key file.
//
// Who "I" am is never the agent's call. The public key (pubkey, rotate,
// --self — everything that decides who can decrypt what gets written) always
// belongs to the key in AGE_SECRET_KEY_FILE. The agent merely saves the
// passphrase prompt when it verifiably holds that very key (Identity.PublicKey
// is set). Otherwise the key file is unlocked as if there were no agent.
type keyAgentIdentity struct {
	*keyagent.Identity
	v       *Vault
	keyFile string
}

func (i *keyAgentIdentity) publicKey() (string, error) {
	if i.PublicKey != "" {
		return i.PublicKey, nil
	}
	id, err := i.v.loadIdentityFile(i.keyFile)
	if err != nil {
		return "", fmt.Errorf("the key agent does not hold the key of AGE_SECRET_KEY_FILE, so it has to be read from the file: %w", err)
	}
	return identityPublicKey(id)
}

// keyAgentIdentity returns an identity backed by the configured key agent, or
// nil if no agent is configured, it is not reachable, or it holds no keys —
// in which case the caller falls back to the key file.
func (v *Vault) keyAgentIdentity() age.Identity {
	keyFile := v.Config.SecretKeyFile
	id := keyagent.NewIdentity(v.Config.KeyAgentSocket, keyFile)
	if id == nil {
		return nil
	}
	// For a file none of the agent's keys can decrypt, try the key file.
	id.Fallback = func() (age.Identity, error) {
		if _, err := os.Stat(keyFile); err != nil {
			return nil, nil
		}
		return v.loadIdentityFile(keyFile)
	}
	return &keyAgentIdentity{Identity: id, v: v, keyFile: keyFile}
}
