# GCP KMS agent/agent-run Compose e2e

A real-world end-to-end check of the `agent`/`agent-run` sidecar pattern from
the main README's "Agent (Sidecar) Mode" section, using an actual GCP KMS key
instead of a locally generated one:

- `secret-agent` resolves the identity via a real `AGE_GCP_KMS_ENCRYPTED_KEY` /
  `GCP_KMS_KEY_NAME` (one real KMS call, at its own startup) and decrypts the
  fixtures in `secrets/`.
- `app` holds no GCP credentials at all — it only reaches `secret-agent` over
  the shared `agent_sock` volume — and still gets the decrypted content.

Both Dockerfiles build the `agevault` binary from this repo's source
(`context: ../..`), so nothing here depends on a pre-built binary.

## Prerequisites

- `gcloud auth application-default login` has been run, and the active
  account can `cloudkms.cryptoKeyVersions.useToDecrypt` on the KMS key below
  (see the main README's "GCP KMS Integration" section).
- Docker with Compose v2, and (on an SELinux-enforcing host) `docker` able to
  relabel bind mounts — `compose.yml` already adds `:Z` to the ones that need
  it.

## `.env` (not committed — git-ignored)

`compose.yml` reads `GCP_KMS_KEY_NAME` and `AGE_GCP_KMS_ENCRYPTED_KEY` from a
`.env` file next to it. It's excluded by a global `.env` gitignore rule, so
anyone (including future-you, on a clean clone) needs to recreate it:

```sh
cat > .env <<EOF
GCP_KMS_KEY_NAME=projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<key>
AGE_GCP_KMS_ENCRYPTED_KEY=<base64 ciphertext from 'gcloud kms encrypt' of an age private key>
EOF
chmod 600 .env
```

See the main README's "☁️ GCP KMS Integration" section for how
`AGE_GCP_KMS_ENCRYPTED_KEY` is produced in the first place (`gcloud kms
encrypt` over an age private key, base64-encoded).

## `secrets/` fixtures (NOT committed — regenerate them yourself)

`secrets/app.env.age` and `secrets/cert.pem.age` must be encrypted to the
public key that the `.env` above's KMS-protected identity corresponds to.
That ties them tightly to one specific real key: swap in a different
`AGE_GCP_KMS_ENCRYPTED_KEY`/`GCP_KMS_KEY_NAME` (a rotated key, someone else's
KMS key, whatever) and these files stop meaning anything — there is no
generic "test ciphertext" here, only ciphertext for the *exact* identity in
your `.env`. So they're gitignored, not committed, and get regenerated
per-`.env`:

```sh
export $(grep -v '^#' .env | xargs)
export AGE_KMS_PROVIDER=gcp

RECIPIENT=$(agevault pubkey)   # resolves via KMS, using the env above

mkdir -p secrets
echo "REAL_GCP_KMS_TEST=it-really-works-via-compose" > secrets/app.env
echo "gcp-kms-backed-cert-data-compose" > secrets/cert.pem
AGE_RECIPIENTS="$RECIPIENT" agevault encrypt secrets/app.env secrets/cert.pem
rm secrets/app.env secrets/cert.pem
```

`agevault pubkey` resolves the identity the same way any other command does
(KMS here), so this is the one real KMS call in the whole setup step — no
plaintext private key ever touches disk.

## Running it

```sh
docker compose up
```

`secret-agent` must report `Healthy` (via `agevault agent-ping`) before `app`
starts — that's what `depends_on: condition: service_healthy` in
`compose.yml` is for; the real KMS round trip takes long enough that `app`
can otherwise start before the socket exists. `app` prints the decrypted env
var and file content, then exits 0. Re-running `docker compose up` reruns
`app` (a one-shot container) against the same still-running `secret-agent`.

## Cleaning up

```sh
docker compose down -v
docker rmi gcp-agent-compose-secret-agent gcp-agent-compose-app
```
