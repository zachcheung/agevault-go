# agevault

`agevault` is a simple utility for managing [age](https://github.com/FiloSottile/age)-encrypted secrets with ease — rewritten in Go.

> This is a Go port of [zachcheung/agevault](https://github.com/zachcheung/agevault).  
> It uses the [`filippo.io/age`](https://pkg.go.dev/filippo.io/age) library directly — no `age` binary required.

---

## 📦 Installation

```sh
go install github.com/zachcheung/agevault-go/cmd/agevault@latest
```

Or build from source:

```sh
git clone https://github.com/zachcheung/agevault-go
cd agevault-go
go install ./cmd/agevault/
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

| Command      | Description                                                                                       | Example                                             |
| ------------ | ------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `encrypt`    | Encrypt file(s)                                                                                   | `agevault encrypt secrets`                          |
|              | `--self` — encrypt using identity (secret key)                                                    | `agevault encrypt --self secrets`                   |
| `decrypt`    | Decrypt `.age` file(s)                                                                            | `agevault decrypt secrets.age`                      |
| `cat`        | Decrypt and print to stdout                                                                       | `agevault cat secrets.age`                          |
| `reencrypt`  | Re-encrypt file(s) with updated recipients file                                                   | `agevault reencrypt secrets.age`                    |
|              | `--all` — re-encrypt all Git-tracked `*.age` files                                                | `agevault reencrypt --all`                          |
| `rotate`     | Re-encrypt file(s) with a new key, update recipients file                                         | `agevault rotate secrets.age`                       |
|              | `--keep-old-key` — keep old key in recipients                                                     | `agevault rotate --keep-old-key secrets.age`        |
|              | `--new-key <file>` — path for new key (default: `./age.key`, or `./age.key.enc` with `--kms-out`) | `agevault rotate --new-key ./new.key secrets.age`   |
|              | `--kms-out` — generate key in memory, write KMS ciphertext to `--new-key`                         | `agevault rotate --kms-out secrets.age`             |
|              | `--all` — rotate all Git-tracked `*.age` files                                                    | `agevault rotate --all`                             |
| `edit`       | Edit encrypted file(s) securely in `$EDITOR`                                                      | `agevault edit secrets.age`                         |
| `run`        | Decrypt `.age` env file(s) into env and run a command                                             | `agevault run env.age -- npm start`                 |
|              | `--env FILES` — load as environment variables                                                     | `agevault run --env secrets.env.age -- npm start`   |
|              | `--decrypt FILES` — decrypt files without loading env                                             | `agevault run --decrypt cert.pem.age -- ./start.sh` |
| `key-add`    | Fetch public key(s) from `AGE_KEY_SERVER`, append to recipients                                   | `agevault key-add alice`                            |
| `key-get`    | Fetch and print a public key from `AGE_KEY_SERVER`                                                | `agevault key-get alice`                            |
| `key-readd`  | Reset recipients file and re-add key(s)                                                           | `agevault key-readd alice bob`                      |
| `completion` | Generate shell completion script                                                                  | `agevault completion zsh`                           |
| `git-setup`  | Configure Git integration for `agevault` diff viewing                                             | `agevault git-setup`                                |

In most cases, `agevault edit` handles encryption, decryption, and editing of secrets in one step.

---

## 📂 Example

```console
$ cd $(mktemp -d)
$ mkdir -pm 0700 ~/.age
$ age-keygen -o ~/.age/age.key && age-keygen -y -o ~/.age/age.pub ~/.age/age.key
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

$ age-keygen -o ./age.key
Public key: age1newkey...
$ cat <(age-keygen -y ./age.key) >> .age.txt

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

## 🔐 Configuration

| Variable                    | Description                                             | Default                                                              |
| --------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------- |
| `AGE_SECRET_KEY`            | Inline private key string (takes precedence)            | (unset)                                                              |
| `AGE_SECRET_KEY_FILE`       | Path to your age private key                            | `~/.age/age.key`                                                     |
| `AGE_RECIPIENTS`            | Comma-separated list of recipients (takes precedence)   | (unset)                                                              |
| `AGE_RECIPIENTS_FILE`       | Path to the recipients list                             | `.age.txt` in same directory as the encrypted file                   |
| `AGE_KEY_SERVER`            | Base URL for remote public keys                         | (must be set to use key commands)                                    |
| `AGE_PUBKEY_EXT`            | Extension for age public keys on the key server         | `pub`                                                                |
| `AGE_KMS_PROVIDER`          | KMS provider: `aws` or `gcp` (required if both are set) | (auto-detected)                                                      |
| `AGE_AWS_KMS_ENCRYPTED_KEY` | Base64 AWS KMS ciphertext of the age private key        | (unset)                                                              |
| `AGE_GCP_KMS_ENCRYPTED_KEY` | Base64 GCP KMS ciphertext of the age private key        | (unset)                                                              |
| `AWS_KMS_KEY_ID`            | AWS KMS key ID / ARN / alias used for decryption        | (inferred from ciphertext metadata); required for `rotate --kms-out` |
| `AWS_REGION`                | AWS region                                              | falls back to `AWS_DEFAULT_REGION`, then SDK default                 |
| `GCP_KMS_KEY_NAME`          | GCP KMS key resource name                               | (required when using GCP KMS)                                        |

> [!NOTE]
> `AGE_KEY_SERVER` **must be set** to use `key-add`, `key-get`, or `key-readd`.
>
> For best security, prefer `AGE_SECRET_KEY_FILE` over `AGE_SECRET_KEY`.
>
> KMS takes precedence over `AGE_SECRET_KEY` / `AGE_SECRET_KEY_FILE`. Provider is auto-detected from which `*_ENCRYPTED_KEY` var is set. If both are set, `AGE_KMS_PROVIDER` must be set to disambiguate.

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
