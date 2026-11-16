# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.1] - 2026-11-16

### Fixed

- Release builds: v0.10.0 and v0.11.0 published no binaries and no container
  image, because the release failed on the windows archive holding one binary
  (`agevault-agent` is not built for windows) while the others hold two; this
  is the first release carrying their changes

## [0.11.0] - 2026-11-16

### Added

- Library: `keyagent` package with the key agent's server and client; it
  depends only on `filippo.io/age`, so a program can decrypt through a running
  `agevault-agent` (`keyagent.NewIdentity`) without importing the rest of
  agevault

### Changed

- Library: the AWS and GCP KMS providers moved to `kms/awskms` and
  `kms/gcpkms` and register themselves on import, so importing the root
  package no longer pulls in the cloud SDKs; a program using KMS-protected
  identities through the library must import the provider it needs
  (`import _ "github.com/zachcheung/agevault-go/kms/awskms"`). The `agevault`
  binary includes both, as before
- Library: `KeyAgent`, `KeyAgentKey`, `KeyAgentAdd`, `KeyAgentList` and
  `KeyAgentClear` moved to the `keyagent` package as `Agent`, `Key`, `Add`,
  `List` and `Clear`
- `agevault-agent` no longer links the cloud SDKs, making the binary about a
  quarter smaller

## [0.10.0] - 2026-11-16

### Added

- Passphrase-protected key files: `AGE_SECRET_KEY_FILE` may be a
  passphrase-encrypted age file (as written by `age -p`), unlocked by a
  terminal prompt once per command, so the private key no longer has to sit
  on disk in plaintext
- `init --passphrase` and `keygen --passphrase` write a new private key
  encrypted with a passphrase
- `passphrase` command: passphrase-protects an existing key file in place, or
  changes its passphrase
- `agevault-agent`, a separate key agent binary (the `ssh-agent` counterpart):
  `serve` holds unlocked keys in memory, `add` unlocks a key file into it
  (optionally with a lifetime), `list` prints the held public keys with the
  key file each came from and `clear` removes them; `agevault` decrypts
  through it when `AGE_KEY_AGENT_SOCKET` is set, so a protected key is
  unlocked once instead of on every command; `pubkey`, `rotate` and `--self`
  always mean the key in `AGE_SECRET_KEY_FILE`, without a prompt when the
  agent holds that key; `agevault-agent completion bash|zsh` generates its
  shell completion
- `AGE_NO_PROMPT=1` makes a command fail immediately instead of asking for a
  key file passphrase, for non-interactive callers (previewers, `git diff`)
- `edit --self` re-encrypts to the current identity alone instead of the
  recipients file, matching `encrypt --self`
- `encrypt --remove` deletes each source file once its `<file>.age` is
  written, so no plaintext copy is left behind

### Changed

- `encrypt` with no file arguments reads stdin and writes ciphertext to
  stdout when stdin is piped, instead of failing with "missing files"
- `git-setup` configures the diff textconv as `AGE_NO_PROMPT=1 agevault cat`,
  so `git diff` fails once instead of prompting for a passphrase per file;
  re-run it in repositories set up by an older version
- Library: `Vault.Init` takes a second `passphrase bool` argument

### Fixed

- `encrypt`, `decrypt`, `reencrypt`, `rotate`, `edit` and `agent-run` replaced
  a symlinked output path with a regular file, leaving the file the link
  pointed to stale; they now replace the link's target and keep the link (a
  dangling link has its target created)

## [0.9.0] - 2026-08-12

### Added

- Named/addressable secrets for `agent`/`agent-run`: `--env`/`--decrypt`
  entries can be tagged with a `name=` prefix, and `agent-run --secret`
  fetches one or more named secrets from an agent serving several
- `agent-ping` command: a readiness probe for `agevault agent`, usable as a
  container `HEALTHCHECK` even against the published shell-less image
- `pubkey` command: prints the public key of the currently configured
  identity, including KMS-protected ones (`keygen -y` only reads local files)
- `agevault encrypt -` reads plaintext from stdin and writes ciphertext to
  stdout instead of `<file>.age`, so the plaintext never has to touch disk

## [0.8.0] - 2026-08-11

### Added

- Agent/agent-run sidecar mode for KMS-free secret delivery

## [0.7.3] - 2026-04-28

### Added

- Support pinning a specific version via `VERSION` env var in the install script

### Fixed

- Handle empty `.age` file in the `edit` command

## [0.7.2] - 2026-04-22

### Fixed

- Use the `age1pq1` prefix to correctly identify PQ keys
- Improve install script completion output
- Drop redundant "Public key:" stderr line when `keygen` writes to stdout

## [0.7.1] - 2026-04-22

### Fixed

- Correct release asset naming in install script and GoReleaser config

## [0.7.0] - 2026-04-22

### Added

- `keygen` command as an `age-keygen` replacement
- `init` command for first-time age key pair setup
- armv7 release builds
- POSIX install script

## [0.6.0] - 2026-04-18

### Added

- `--pq` flag to `rotate` for post-quantum hybrid key generation
- Guard against mixing classic/PQ recipients on `rotate --keep-old-key`
- Automatic preservation of PQ key type on rotate

## [0.5.0] - 2026-04-16

### Added

- `--kms-out` flag to `rotate` for KMS-safe key rotation

### Fixed

- Resolve recipients file when `AGE_RECIPIENTS` is set during rotate

## [0.4.0] - 2026-04-15

### Added

- Publish container images to GHCR via `ko`

## [0.3.0] - 2026-04-15

### Added

- GCP KMS support with auto-detected or explicit provider

### Changed

- Replace GCP KMS SDK with a direct REST API call

## [0.2.0] - 2026-04-15

### Added

- AWS KMS integration for age key decryption

## [0.1.0] - 2026-04-14

### Added

- Initial Go port of `agevault`
- Version command with build-time injection
- GoReleaser config and GitHub Actions workflows

[Unreleased]: https://github.com/zachcheung/agevault-go/compare/v0.11.1...HEAD
[0.11.1]: https://github.com/zachcheung/agevault-go/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/zachcheung/agevault-go/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/zachcheung/agevault-go/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/zachcheung/agevault-go/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/zachcheung/agevault-go/compare/v0.7.3...v0.8.0
[0.7.3]: https://github.com/zachcheung/agevault-go/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/zachcheung/agevault-go/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/zachcheung/agevault-go/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/zachcheung/agevault-go/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/zachcheung/agevault-go/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/zachcheung/agevault-go/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/zachcheung/agevault-go/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zachcheung/agevault-go/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zachcheung/agevault-go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zachcheung/agevault-go/releases/tag/v0.1.0
