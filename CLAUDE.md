# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`agevault` is a CLI for managing [age](https://github.com/FiloSottile/age)-encrypted secrets. It's a Go port of the original shell-script `agevault`, using `filippo.io/age` directly (no `age` binary required). Supports classic X25519 and post-quantum hybrid (ML-KEM-768+X25519) keys, plus AWS/GCP KMS-wrapped identities for CI use.

## Commands

```sh
# Build (matches CI in .github/workflows/test.yml)
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath ./...

# Run all tests
go test -v ./...

# Run a single test
go test -v -run TestName ./...

# Run the CLI during development (use `go run`, not `go build`, for iterating on cmd behavior)
go run ./cmd/agevault <command> [args...]
```

Releases are cut via GoReleaser (`.goreleaser.yaml`) triggered by pushing a `v*` tag (`.github/workflows/release.yml`), which also builds/pushes a `ghcr.io/zachcheung/agevault` image.

## Architecture

The repo is a single Go module split into two layers:

- **`package agevault`** (root directory) — all core logic, exported so it can be driven programmatically and unit-tested without a subprocess.
- **`cmd/agevault-agent`** — a second, thin binary: the key agent (`serve`/`add`/`list`/`clear`), all logic in `keyagent.go`. Not to be confused with the `agent` sidecar verb of the main binary.
- **`cmd/agevault`** — the CLI entrypoint. `main.go` does manual `flag.FlagSet`-based parsing per subcommand and calls into `agevault.NewVault()` methods. There is no CLI framework; each `cmd*` function in `main.go` owns its own usage text and flags.

Core type: `Vault` (`config.go`), holding a `*Config` loaded from env vars via `NewVault()`. Nearly every operation is a method on `*Vault`. `Vault.KMSDecryptor` is an injectable override point for tests to avoid making real KMS calls.

File responsibilities:
- `config.go` — `Config`/`Vault` structs, env var loading (`NewVault`).
- `crypto.go` — identity/recipient resolution (`GetIdentity`, `GetRecipients`), low-level encrypt/decrypt to io.Reader/Writer, key generation (`GenerateIdentity`, `GenerateHybridIdentityToFile`, `KeygenToWriter`).
- `vault.go` — the main verbs: `Encrypt` (including `-` for stdin/stdout), `Decrypt`, `Cat`, `Reencrypt`, `Rotate`, `Edit`, `Init`. Multi-file git integration (`--all`) via `gitListAgeFiles()`.
- `run.go` — the `run` verb: decrypts env/files then `syscall.Exec`s a command, replacing the process. `ParseRunArgs` hand-parses `--env`, `--decrypt`, `--`, and legacy bare-positional-args-as-env-files.
- `agent.go` — the sidecar trio `agent`/`agent-run`/`agent-ping`: `RunAgent` resolves the identity and decrypts `--env`/`--decrypt` files exactly once at startup (grouped into named secrets via an optional `name=` prefix on each entry, see `namedFile`/`buildAgentBundles`), then serves them as JSON over a Unix socket. Each client sends an `agentRequest` naming which secret(s) it wants (empty = the default/unnamed one) and the server merges the requested named bundles (`mergeNamedBundles`) into one `AgentBundle` response — `DialAgentBundle`/`ApplyAgentBundle`/`AgentRun` are the client side; `PingAgent` is a bare connect-and-close readiness check (used by `agent-ping`, since the published image is shell-less and can't run a `test -S`-style healthcheck).
- `passphrase.go` — passphrase-protected key files: `loadIdentityFile` (used by `GetIdentity`, `keygen -y`, `rotate`'s existing `--new-key`) detects an age-encrypted key file (armored or binary, scrypt — the `age -p` format), prompts on `/dev/tty`, and caches the unlocked identity on the `Vault` so one command prompts once. `Vault.PassphrasePrompt` is the injectable override for tests; `Config.NoPrompt` (`AGE_NO_PROMPT`) makes any prompt an immediate error instead, for non-interactive callers. Also the `passphrase` verb (`SetKeyPassphrase`) and the `--passphrase` variants of `init`/`keygen`.
- `keyagent.go` (+ `keyagent_linux.go`/`keyagent_other.go` for the non-dumpable hardening) — the ssh-agent-style key agent behind the `agevault-agent` binary: `KeyAgent.Serve` holds unlocked identities in memory and answers one JSON request per connection on `AGE_KEY_AGENT_SOCKET` — `add` (plaintext key in, optional lifetime), `list` (public keys + source key file + key file fingerprints), `clear`, `unwrap` (header stanzas in, that file's file key out; the private key never leaves). Client side: `keyAgentIdentity` implements `age.Identity` by forwarding `Unwrap`, so every verb works unchanged. Keys are only ever added explicitly (`agevault-agent add`), never automatically by the client.
- `key.go` — `key-add`/`key-get`/`key-readd`, fetching public keys from `AGE_KEY_SERVER` (http(s):// or file://).
- `kms.go` / `kms_aws.go` / `kms_gcp.go` — `KeyDecryptor`/`KeyEncryptor` interfaces; provider auto-detection from which `*_ENCRYPTED_KEY` env var is set (`AGE_KMS_PROVIDER` disambiguates if both are set). Add a new provider by implementing both interfaces and wiring it into `resolveKMS`/`newKMSDecryptor`/`newKMSEncryptor`.
- `gitsetup.go` — `git-setup` verb: configures `diff.agevault.textconv` and `.gitattributes` so `git diff` shows decrypted content.

### Key precedence and conventions worth knowing

- Identity resolution order (`GetIdentity` in `crypto.go`): KMS ciphertext (if configured) > `AGE_SECRET_KEY` (inline) > key agent (`AGE_KEY_AGENT_SOCKET`, only if reachable and holding a key — otherwise silently falls through) > `AGE_SECRET_KEY_FILE`. The agent is for decryption only: `Unwrap` tries all its keys, then (if none fits and the agent doesn't already hold the key file's key) the key file. "My public key" (`pubkey`/`rotate`/`--self`) is ALWAYS the key in `AGE_SECRET_KEY_FILE`, never whatever the agent happens to hold — not even a sole key. The agent only saves the prompt: `agevault-agent add` sends a SHA-256 of the key file's on-disk bytes (`keyFileFingerprint`; the recorded path is a display label only), and the client matches the key file's fingerprint against the agent's keys to learn its public key without unlocking; no match → `loadIdentityFile` as if there were no agent. `pubkey` prints the public half of whatever this resolves to (including KMS-protected identities) — `keygen -y <file>` only ever reads a local key file, so it can't do that.
- Recipients resolution (`GetRecipients`): `AGE_RECIPIENTS` (inline, comma-separated) takes precedence over the recipients file (`AGE_RECIPIENTS_FILE`, default `.age.txt` next to the secret file). For `agent`'s `--env`/`--decrypt` (stdin-less) and `encrypt -` (stdin), there is no secret file path to resolve `.age.txt` alongside, so recipients resolve relative to the current directory instead.
- Post-quantum keys are distinguished by the `age1pq1` public-key prefix (see `parseRecipient` in `crypto.go`); `rotate` auto-preserves PQ-ness unless `--pq` is passed, and refuses to mix classic/PQ recipients under `--keep-old-key`.
- All file writes that replace an existing file (encrypt, decrypt, reencrypt, rotate, edit) go through a temp file in the same directory + atomic `os.Rename`, never an in-place write. The rename destination always goes through `replaceTarget()` first, so a symlinked path has its target replaced and the link kept (a dangling link gets its target created; a link is never replaced) — renaming straight onto a path silently swaps a symlink for a regular file. The one exception is `encrypt -`/agent's stdin-stdout and socket paths, where there's nothing to make atomic (a pipe, not a file).
- `Rotate` and `Reencrypt --all` operate on Git-tracked `*.age` files via `git ls-files`, resolved from the repo root — not a plain filesystem glob.
- `agent`'s `--decrypt` files are served keyed by the *basename* of their decrypted path (directory and `.age` suffix stripped) — the agent's own filesystem layout has no meaning to a client in a different container. Two entries in the same named secret that reduce to the same basename are rejected at agent startup rather than silently colliding.
- `--env`/`--decrypt` (on `agent`) are single-value flags parsed by Go's `flag` package: passing either flag twice keeps only the *last* value. Multiple entries — named or not — must go in one comma-separated `--env a,b` / `--decrypt a,b`, never `--env a --env b`.

## Testing

Two established patterns, both in the root package (`package agevault_test`):
- `vault_test.go` (root command coverage), `vault_kms_test.go` (KMS-specific, using a `mockDecryptor`/`mockEncryptor` to avoid real cloud calls), and `agent_test.go` (agent/agent-run/agent-ping, real Unix sockets in `t.TempDir()`) construct a `Vault` directly and call its methods — no subprocess.
- `cli_e2e_test.go` builds the real `agevault` binary once (`sync.Once`) and drives it as an actual subprocess across the full command set, mirroring the old shell version's `agevault_test.sh` coverage. Each case gets its own `t.TempDir()` and an explicit per-`exec.Command` environment (never `t.Setenv`/the parent process's env), so cases never affect each other and are safe to run with `t.Parallel()`.

Use the direct-`Vault` pattern for testing library logic in isolation; use the `cli_e2e_test.go` subprocess pattern when the thing under test is CLI-layer behavior itself (flag parsing in `main.go`, real process exec, real socket files) that the library-level tests can't reach.

There's also a real-infrastructure manual check under `e2e/gcp-agent-compose/` (not part of `go test`) — a Docker Compose stack exercising `agent`/`agent-run` against an actual GCP KMS key. See its README for prerequisites and how to regenerate its gitignored `.env`/fixtures.
