# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/zachcheung/agevault-go/compare/v0.8.0...HEAD
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
