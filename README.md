# agevault

`agevault` is a simple utility for managing [age](https://github.com/FiloSottile/age)-encrypted secrets with ease — rewritten in Go.

> This is a Go port of [zachcheung/agevault](https://github.com/zachcheung/agevault).  
> It uses the [`filippo.io/age`](https://pkg.go.dev/filippo.io/age) library directly — no `age` binary required.

---

## 📦 Installation

**Install script** (Linux / macOS):

```sh
curl -fsSL https://raw.githubusercontent.com/zachcheung/agevault-go/main/install.sh | sh
```

Install to a custom directory:

```sh
curl -fsSL https://raw.githubusercontent.com/zachcheung/agevault-go/main/install.sh | INSTALL_DIR=~/.local/bin sh
```

**Go install:**

```sh
go install github.com/zachcheung/agevault-go/cmd/agevault@latest
go install github.com/zachcheung/agevault-go/cmd/agevault-agent@latest  # optional key agent
```

**Docker / container image** — copy the binary into your own image:

```dockerfile
COPY --from=ghcr.io/zachcheung/agevault:latest /ko-app/agevault /usr/local/bin/agevault
```

Or pin to a specific version:

```dockerfile
COPY --from=ghcr.io/zachcheung/agevault:0.7 /ko-app/agevault /usr/local/bin/agevault
```

---

## 🧠 Shell Completion

**Bash** — install globally:

```sh
agevault completion bash | sudo tee /usr/share/bash-completion/completions/agevault > /dev/null
```

Or per-user (`~/.bashrc`):

```sh
source <(agevault completion bash)
```

`agevault-agent` ships its own script the same way: `agevault-agent completion bash|zsh`.

**Zsh:**

```sh
mkdir -p ~/.zsh/completions
agevault completion zsh > ~/.zsh/completions/_agevault
```

Then add to `~/.zshrc`:

```sh
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit && compinit
```

---

## 🚀 Usage

By default, `agevault` expects an age recipients file named `.age.txt` in the same directory as the secret file. Override with `AGE_RECIPIENTS` or `AGE_RECIPIENTS_FILE`.

| Command      | Description                                                                                                                     | Example                                             |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `encrypt`    | Encrypt file(s)                                                                                                                 | `agevault encrypt secrets`                          |
|              | `--self` — encrypt using identity (secret key)                                                                                  | `agevault encrypt --self secrets`                   |
|              | `--remove` — delete each source file once it is encrypted                                                                       | `agevault encrypt --remove secrets`                 |
|              | `-` — read stdin, write ciphertext to stdout (plaintext never touches disk)                                                     | `echo hi \| agevault encrypt - > s.age`             |
| `decrypt`    | Decrypt `.age` file(s)                                                                                                          | `agevault decrypt secrets.age`                      |
| `cat`        | Decrypt and print to stdout                                                                                                     | `agevault cat secrets.age`                          |
| `reencrypt`  | Re-encrypt file(s) with updated recipients file                                                                                 | `agevault reencrypt secrets.age`                    |
|              | `--all` — re-encrypt all Git-tracked `*.age` files                                                                              | `agevault reencrypt --all`                          |
| `rotate`     | Re-encrypt file(s) with a new key, update recipients file                                                                       | `agevault rotate secrets.age`                       |
|              | `--keep-old-key` — keep old key in recipients                                                                                   | `agevault rotate --keep-old-key secrets.age`        |
|              | `--new-key <file>` — path for new key (default: `./age.key`, or `./age.key.enc` with `--kms-out`)                               | `agevault rotate --new-key ./new.key secrets.age`   |
|              | `--kms-out` — generate key in memory, write KMS ciphertext to `--new-key`                                                       | `agevault rotate --kms-out secrets.age`             |
|              | `--pq` — upgrade to post-quantum hybrid ML-KEM-768+X25519 key (all recipients must be hybrid; auto-preserved if already hybrid) | `agevault rotate --pq secrets.age`                  |
|              | `--all` — rotate all Git-tracked `*.age` files                                                                                  | `agevault rotate --all`                             |
| `edit`       | Edit encrypted file(s) securely in `$EDITOR`                                                                                    | `agevault edit secrets.age`                         |
|              | `--self` — re-encrypt using identity (secret key) instead of recipients file                                                    | `agevault edit --self secrets.age`                  |
| `run`        | Decrypt `.age` env file(s) into env and run a command                                                                           | `agevault run env.age -- npm start`                 |
|              | `--env FILES` — load as environment variables                                                                                   | `agevault run --env secrets.env.age -- npm start`   |
|              | `--decrypt FILES` — decrypt files without loading env                                                                           | `agevault run --decrypt cert.pem.age -- ./start.sh` |
| `init`       | Generate a new age key pair at `AGE_SECRET_KEY_FILE` (default: `~/.age/age.key`); fails if file exists                          | `agevault init`                                     |
|              | `--pq` — generate a post-quantum hybrid ML-KEM-768+X25519 key                                                                   | `agevault init --pq`                                |
|              | `--passphrase` — protect the private key with a passphrase                                                                      | `agevault init --passphrase`                        |
| `keygen`     | Generate a new age key pair (no `age-keygen` needed)                                                                            | `agevault keygen`                                   |
|              | `-o <file>` — write private key to file                                                                                         | `agevault keygen -o ~/.age/age.key`                 |
|              | `--pq` — generate a post-quantum hybrid ML-KEM-768+X25519 key                                                                   | `agevault keygen --pq -o ~/.age/age.key`            |
|              | `--passphrase` — protect the private key with a passphrase                                                                      | `agevault keygen --passphrase -o ~/.age/age.key`    |
|              | `-y <file>` — print the public key of an existing private key file                                                              | `agevault keygen -y ~/.age/age.key`                 |
| `passphrase` | Passphrase-protect an existing key file in place, or change its passphrase (default: `AGE_SECRET_KEY_FILE`)                     | `agevault passphrase ~/.age/age.key`                |
| `pubkey`     | Print the public key of the current identity (works for KMS-protected identities too)                                           | `agevault pubkey`                                   |
| `agent`      | Run a sidecar: decrypt `--env`/`--decrypt` file(s) once, serve over socket (`--socket`, default `AGE_AGENT_SOCKET`)             | `agevault agent --socket a.sock --env app.env.age`  |
| `agent-run`  | Fetch decrypted content from `agevault agent` (`--socket`, default `AGE_AGENT_SOCKET`), then run a command                      | `agevault agent-run --socket a.sock -- npm start`   |
| `agent-ping` | Check whether `agevault agent` is listening (for container healthchecks)                                                        | `agevault agent-ping --socket a.sock`               |
| `key-add`    | Fetch public key(s) from `AGE_KEY_SERVER`, append to recipients                                                                 | `agevault key-add alice`                            |
| `key-get`    | Fetch and print a public key from `AGE_KEY_SERVER`                                                                              | `agevault key-get alice`                            |
| `key-readd`  | Reset recipients file and re-add key(s)                                                                                         | `agevault key-readd alice bob`                      |
| `completion` | Generate shell completion script                                                                                                | `agevault completion zsh`                           |
| `git-setup`  | Configure Git integration for `agevault` diff viewing                                                                           | `agevault git-setup`                                |

In most cases, `agevault edit` handles encryption, decryption, and editing of secrets in one step.

---

## 📂 Example

```console
$ cd $(mktemp -d)
$ agevault init
Generated new age key pair:

  Private key: ~/.age/age.key
  Public key:  ~/.age/age.pub

Public key: age1...
$ cp ~/.age/age.pub .age.txt
$ echo "my secret" > secrets

$ agevault encrypt secrets
'secrets' is encrypted to 'secrets.age'.
$ rm secrets

# Encrypt using your own identity (no recipients file needed)
$ agevault encrypt --self secrets
'secrets' is encrypted to 'secrets.age'.

$ agevault decrypt secrets.age
'secrets.age' is decrypted to 'secrets'.

$ cat secrets && rm secrets
my secret

$ agevault cat secrets.age
my secret

$ agevault edit secrets.age
'secrets.age' is updated.

$ agevault cat secrets.age
my new secret

$ agevault keygen -o ./age.key
Public key: age1newkey...
$ agevault keygen -y ./age.key >> .age.txt

# Re-encrypt with the new recipient included
$ agevault reencrypt secrets.age
'secrets.age' is reencrypted.

# Now decryption with the new key works
$ AGE_SECRET_KEY_FILE=./age.key agevault cat secrets.age
my new secret
```

---

## 🏃 Run Command Examples

**Environment Mode (default — backwards compatible):**

```console
$ echo "API_KEY=secret123" > .env
$ agevault encrypt .env
$ agevault run .env.age -- curl -H "Authorization: Bearer $API_KEY" api.example.com
```

**Explicit Environment Mode:**

```console
$ echo "DB_PASSWORD=secret" > database.env
$ agevault encrypt database.env
$ agevault run --env database.env.age -- ./deploy.sh
```

**Decrypt-only Mode:**

```console
$ echo "sensitive data" > secret.txt
$ agevault encrypt secret.txt
$ agevault run --decrypt secret.txt.age -- cat secret.txt
sensitive data
```

**Combined Mode:**

```console
$ agevault run --env config.env.age --decrypt cert.pem.age -- docker run -v $(pwd):/data myapp
```

**Comma-separated Files:**

```console
$ agevault run --env "app.env.age,db.env.age" --decrypt "cert.pem.age,key.pem.age" -- ./start-server.sh
```

---

## 🕵️ Agent (Sidecar) Mode

For container/Compose setups where a client shouldn't hold KMS or age
credentials at all, run `agevault agent` as a long-lived sidecar: it resolves
the identity and decrypts the given files once at startup, then serves the
result over a Unix socket. `agevault agent-run` connects to that socket,
applies the decrypted env vars/files, and execs a command — no identity,
recipients, or KMS access needed on the client side.

```console
$ agevault agent --socket ./agent.sock --env app.env.age --decrypt cert.pem.age &
[INFO] agevault agent listening on ./agent.sock

$ agevault agent-run --socket ./agent.sock -- sh -c 'echo $API_KEY; cat cert.pem'
secret123
-----BEGIN CERTIFICATE-----...
```

Stop the agent (`Ctrl-C` or `SIGTERM`) and it removes the socket file and exits.

`--decrypt` files are served keyed by **basename only** — directory and
`.age` suffix stripped — since the agent's own filesystem layout has no
meaning to a client running in a different container. `agent-run` writes each
one directly into its own current directory under that basename; there's no
flag to pick which files to fetch or where they land, since the agent already
decided that with its own `--decrypt` list. This also means two `--decrypt`
files that reduce to the same basename (e.g. `a/cert.pem.age` and
`b/cert.pem.age`) can't both be served — `agevault agent` fails at startup
rather than letting one silently overwrite the other in the bundle.

**Named secrets** — one agent can hold several independent secrets instead of
always serving one fixed bundle. Tag any `--env`/`--decrypt` entry with a
`name=` prefix to route it into that named secret; untagged entries fall into
the default (unnamed) secret. `agent-run --secret <names>` then fetches one
or more named secrets by name (comma-separated names are merged into one
bundle) instead of getting everything the agent holds:

```console
$ agevault agent --socket ./agent.sock \
    --env db=db.env.age,cert=cert.env.age \
    --decrypt db=db-ca.pem.age &

$ agevault agent-run --socket ./agent.sock --secret db -- sh -c 'echo $DB_PASSWORD; cat db-ca.pem'
dbsecret
-----BEGIN CERTIFICATE-----...

$ agevault agent-run --socket ./agent.sock --secret db,cert -- ./start-app.sh
```

Requesting a name the agent doesn't serve (or omitting `--secret` when the
agent has no default/unnamed secret configured) fails with the list of
secrets the agent actually has, rather than silently returning nothing.

**Docker Compose example** — a sidecar decrypts once and caches the plaintext
in memory; the app container never sees KMS credentials or the age identity.
The mount is namespaced under `/run/agevault-agent` so it doesn't collide with
some other tool's socket in the app's own image:

```yaml
services:
  secret-agent:
    image: ghcr.io/zachcheung/agevault:latest
    restart: unless-stopped
    command: ["agent", "--socket", "/run/agevault-agent/agent.sock", "--env", "/secrets/app.env.age"]
    environment:
      AGE_AWS_KMS_ENCRYPTED_KEY: ${AGE_AWS_KMS_ENCRYPTED_KEY}
      AWS_KMS_KEY_ID: ${AWS_KMS_KEY_ID}
    volumes:
      - agent_sock:/run/agevault-agent
      - ./secrets/app.env.age:/secrets/app.env.age:ro
    healthcheck:
      test: ["CMD", "agevault", "agent-ping", "--socket", "/run/agevault-agent/agent.sock"]
      interval: 1s
      retries: 30

  app:
    build: .
    depends_on:
      secret-agent:
        condition: service_healthy
    volumes:
      - agent_sock:/run/agevault-agent

volumes:
  agent_sock:
```

`restart: unless-stopped` means only a `secret-agent` restart re-triggers the
KMS call — redeploying or crash-looping `app` does not. The socket file's
permissions (mode `0600`) are the access control; anything that can reach
`agent.sock` can read the bundle, so mount the shared volume only into
containers that need it.

`depends_on: condition: service_healthy` — not the default `service_started` — matters
here: `secret-agent`'s process can take a moment (a real KMS round trip) between its
container starting and its socket actually existing, so without the healthcheck `app`
can start and try to connect before the socket is there. The published `agevault` image
has no shell (it's built on a distroless base), so the healthcheck has to invoke
`agevault` directly in exec form — `agent-ping` exists specifically to make that
possible.

Note the `app` service above has no `entrypoint`/`command` override — setting
`entrypoint:` in the compose file would fully replace whatever ENTRYPOINT the
app's own image already runs (an init wrapper like `tini`, a base image's own
`docker-entrypoint.sh`, etc.), and it hardcodes the socket path and real
command in the compose file rather than in the image itself. Instead, bake the
`agent-run` wrapping into the app's **own** `Dockerfile`, alongside the
`COPY --from=ghcr.io/zachcheung/agevault:latest` step from the installation
section above:

```dockerfile
COPY --from=ghcr.io/zachcheung/agevault:latest /ko-app/agevault /usr/local/bin/agevault
ENTRYPOINT ["agevault", "agent-run", "--socket", "/run/agevault-agent/agent.sock", "--"]
CMD ["npm", "start"]
```

`agevault agent-run --socket ... --` is the `ENTRYPOINT` rather than the `CMD`
because Docker always runs `ENTRYPOINT` and only appends `CMD` (or a
`docker run`/Compose `command:` override) as its trailing arguments — it never
replaces `ENTRYPOINT` itself. Putting the secret-fetch-and-exec wrapper there
means it always runs no matter what command the container ends up starting;
putting it in `CMD` instead would mean a `command:` override (a different
deployment reusing this image for `node worker.js`, a one-off
`docker run image sh`, etc.) silently skips fetching the secret entirely,
since overriding `CMD` replaces it wholesale rather than extending it.

The trailing `"--"` in `ENTRYPOINT` is also what makes the two layers line up:
in exec form, Docker runs `ENTRYPOINT` with `CMD` appended as its arguments,
so the array above resolves to exactly
`agevault agent-run --socket /run/agevault-agent/agent.sock -- npm start` —
the same `--`-separated form `agent-run` expects from the command line, just
assembled by Docker instead of typed by hand. Compose can still override just
the app's own command with `command:` (e.g. `command: ["node", "worker.js"]`)
without ever having to repeat or bypass the `agevault agent-run` wrapper.

---

## 🔐 Configuration

| Variable                    | Description                                                                                          | Default                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `AGE_SECRET_KEY`            | Inline private key string (takes precedence)                                                         | (unset)                                                              |
| `AGE_SECRET_KEY_FILE`       | Path to your age private key (plain or passphrase-protected)                                         | `~/.age/age.key`                                                     |
| `AGE_RECIPIENTS`            | Comma-separated list of recipients (takes precedence)                                                | (unset)                                                              |
| `AGE_RECIPIENTS_FILE`       | Path to the recipients list                                                                          | `.age.txt` in same directory as the encrypted file                   |
| `AGE_KEY_SERVER`            | Base URL for remote public keys                                                                      | (must be set to use key commands)                                    |
| `AGE_PUBKEY_EXT`            | Extension for age public keys on the key server                                                      | `pub`                                                                |
| `AGE_KMS_PROVIDER`          | KMS provider: `aws` or `gcp` (required if both are set)                                              | (auto-detected)                                                      |
| `AGE_AWS_KMS_ENCRYPTED_KEY` | Base64 AWS KMS ciphertext of the age private key                                                     | (unset)                                                              |
| `AGE_GCP_KMS_ENCRYPTED_KEY` | Base64 GCP KMS ciphertext of the age private key                                                     | (unset)                                                              |
| `AWS_KMS_KEY_ID`            | AWS KMS key ID / ARN / alias used for decryption                                                     | (inferred from ciphertext metadata); required for `rotate --kms-out` |
| `AWS_REGION`                | AWS region                                                                                           | falls back to `AWS_DEFAULT_REGION`, then SDK default                 |
| `GCP_KMS_KEY_NAME`          | GCP KMS key resource name                                                                            | (required when using GCP KMS)                                        |
| `AGE_AGENT_SOCKET`          | Unix socket path for `agent` / `agent-run`                                                           | (unset)                                                              |
| `AGE_KEY_AGENT_SOCKET`      | Unix socket path of the `agevault-agent` key agent                                                   | (unset)                                                              |
| `AGE_NO_PROMPT`             | Set to `1` to fail instead of asking for a key file passphrase (for previewers, `git diff`, scripts) | (unset)                                                              |

> [!NOTE]
> `AGE_KEY_SERVER` **must be set** to use `key-add`, `key-get`, or `key-readd`.
>
> For best security, prefer `AGE_SECRET_KEY_FILE` over `AGE_SECRET_KEY`, and passphrase-protect the key file (see below).
>
> Identity precedence: KMS > `AGE_SECRET_KEY` > key agent (`AGE_KEY_AGENT_SOCKET`) > `AGE_SECRET_KEY_FILE`. Provider is auto-detected from which `*_ENCRYPTED_KEY` var is set. If both are set, `AGE_KMS_PROVIDER` must be set to disambiguate.

---

## 🔑 Passphrase-Protected Key File

By default the private key in `AGE_SECRET_KEY_FILE` is stored in plaintext. To keep it encrypted at rest, protect it with a passphrase:

```sh
# New key, written encrypted — the plaintext key never touches disk
agevault init --passphrase

# Existing key: encrypt it in place (run again later to change the passphrase)
agevault passphrase ~/.age/age.key
```

Every command that needs the identity then asks for the passphrase on the terminal (once per command, however many files it touches). The prompt uses the controlling terminal directly, so piping stdin/stdout keeps working (`agevault cat secrets.age | ...`); with no terminal available the command fails instead of prompting.

A protected key file is an ordinary passphrase-encrypted age file (what `age -p -a` writes), so it also works as an identity file with the `age` CLI, and a key file encrypted with `age -p` works with agevault.

### Key agent (`agevault-agent`)

To avoid typing the passphrase on every command, run `agevault-agent` — the `ssh-agent` counterpart for age keys. It holds unlocked keys in memory only and does the private-key part of decryption for `agevault`; private keys go in but never come back out.

```sh
export AGE_KEY_AGENT_SOCKET="$XDG_RUNTIME_DIR/agevault-agent.sock"

agevault-agent serve &        # or as a user service, see below
agevault-agent add            # asks for the passphrase once
agevault cat secrets.age      # no prompt
```

| Command                                | Description                                                                                    |
| -------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `agevault-agent serve`                 | Run the agent in the foreground; it starts with no keys                                        |
| `agevault-agent add [-t 8h] [keyfile]` | Unlock a key file (default: `AGE_SECRET_KEY_FILE`) and add it; `-t` forgets it after that long |
| `agevault-agent list`                  | Print the public keys of the keys the agent holds                                              |
| `agevault-agent clear`                 | Remove all keys from the agent                                                                 |

`agevault` uses the agent whenever `AGE_KEY_AGENT_SOCKET` is set and the agent holds a key. If the agent is not running or is empty, it falls back to `AGE_SECRET_KEY_FILE` (and its passphrase prompt), as `ssh` does with an empty `ssh-agent`. When the agent holds several keys, decryption tries all of them; commands that need *your* public key (`pubkey`, `rotate`, `--self`) use the first one added.

For callers that must never stop at a prompt — a file-manager previewer, `git diff` textconv, a script — set `AGE_NO_PROMPT=1`: with the agent empty or not running, the command then fails immediately with a hint to run `agevault-agent add`, instead of asking for the passphrase. `agevault git-setup` configures the diff textconv this way; re-run it to update a repository set up by an older version.

Any process running as you can ask the agent to decrypt while a key is loaded (the socket is mode `0600`) — the same trust model as `ssh-agent`. On Linux the agent also marks itself non-dumpable, so other processes of yours cannot read its memory.

Example systemd user unit (`~/.config/systemd/user/agevault-agent.service`):

```ini
[Unit]
Description=agevault key agent

[Service]
Environment=AGE_KEY_AGENT_SOCKET=%t/agevault-agent.sock
ExecStart=%h/go/bin/agevault-agent serve

[Install]
WantedBy=default.target
```

> [!NOTE]
> `agevault-agent` is unrelated to the `agevault agent` sidecar: the sidecar serves already-decrypted secrets to other containers, while `agevault-agent` holds your key on your own machine.

---

## ☁️ AWS KMS Integration

Storing a plaintext age private key in CI (e.g. GitLab CI, GitHub Actions) is a security risk — any job can `echo` it. Instead, encrypt the key with AWS KMS and store only the ciphertext. At runtime, `agevault` calls KMS to decrypt the key, using the IAM role attached to the runner.

**Encrypt your age key with KMS:**

```sh
aws kms encrypt \
  --key-id alias/<key-alias> \
  --region <region> \
  --plaintext fileb://~/.age/age.key \
  --query CiphertextBlob \
  --output text
```

Store the output as `AGE_AWS_KMS_ENCRYPTED_KEY` in your CI secrets.

**CI configuration (GitLab CI example):**

```yaml
variables:
  AGE_AWS_KMS_ENCRYPTED_KEY: $AGE_AWS_KMS_ENCRYPTED_KEY  # set in CI secrets

deploy:
  script:
    - agevault run --env config.env.age -- ./deploy.sh
```

The runner's IAM role must have `kms:Decrypt` permission on the KMS key. No plaintext key is ever stored in CI.

> [!NOTE]
> `AWS_KMS_KEY_ID` is optional — AWS KMS can infer the key from the ciphertext metadata.

**Rotating the KMS-protected key in CI:**

```sh
# Requires kms:Encrypt permission. AWS_KMS_KEY_ID must be set.
agevault rotate --kms-out secrets.age
# → generates a new key in memory, writes KMS ciphertext to ./age.key.enc
```

---

## ☁️ GCP KMS Integration

**Encrypt your age key with GCP KMS:**

```sh
gcloud kms encrypt \
  --key <key> \
  --keyring <keyring> \
  --location <location> \
  --project <project> \
  --plaintext-file ~/.age/age.key \
  --ciphertext-file - | base64
```

Store the output as `AGE_GCP_KMS_ENCRYPTED_KEY` and set `GCP_KMS_KEY_NAME`:

```sh
export AGE_GCP_KMS_ENCRYPTED_KEY=<base64-ciphertext>
export GCP_KMS_KEY_NAME='projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<key>'
```

The service account attached to the runner must have `cloudkms.cryptoKeyVersions.useToDecrypt` permission on the key.

**Rotating the KMS-protected key in CI:**

```sh
# Requires cloudkms.cryptoKeyVersions.useToEncrypt permission.
agevault rotate --kms-out secrets.age
# → generates a new key in memory, writes KMS ciphertext to ./age.key.enc
```

> [!NOTE]
> For local development, run `gcloud auth application-default login` — the Go client libraries use ADC separately from `gcloud` CLI credentials.

---

## 🌐 Key Management

```sh
export AGE_KEY_SERVER="https://keys.example.com"
```

By default, `agevault` fetches each key from `$AGE_KEY_SERVER/<username>.pub`.

---

## License

[MIT](LICENSE)
