package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	agevault "github.com/zachcheung/agevault-go"
)

// version is set at build time via -ldflags "-X main.version=v1.2.3".
var version = "HEAD"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stdout, helpText)
		os.Exit(0)
	}

	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "encrypt":
		err = cmdEncrypt(args)
	case "decrypt":
		err = cmdDecrypt(args)
	case "cat":
		err = cmdCat(args)
	case "reencrypt":
		err = cmdReencrypt(args)
	case "rotate":
		err = cmdRotate(args)
	case "edit":
		err = cmdEdit(args)
	case "run":
		err = cmdRun(args)
	case "agent":
		err = cmdAgent(args)
	case "agent-run":
		err = cmdAgentRun(args)
	case "agent-ping":
		err = cmdAgentPing(args)
	case "key-add":
		err = cmdKeyAdd(args)
	case "key-get":
		err = cmdKeyGet(args)
	case "key-readd":
		err = cmdKeyReadd(args)
	case "init":
		err = cmdInit(args)
	case "keygen":
		err = cmdKeygen(args)
	case "pubkey":
		err = cmdPubkey(args)
	case "completion":
		err = cmdCompletion(args)
	case "git-setup":
		err = cmdGitSetup(args)
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, helpText)
	default:
		fmt.Fprintf(os.Stderr, "agevault: unknown command %q\n\n%s", cmd, helpText)
		os.Exit(1)
	}

	if err != nil && err != flag.ErrHelp {
		fmt.Fprintf(os.Stderr, "agevault %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// ── encrypt ──────────────────────────────────────────────────────────────────

func cmdEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault encrypt [--self] <file>...

Encrypt one or more files. Output is written to <file>.age.

By default recipients are read from AGE_RECIPIENTS or .age.txt next to each
file. With --self the current identity is the sole recipient.

A file argument of "-" reads plaintext from stdin and writes ciphertext to
stdout instead of <file>.age, so the plaintext never touches disk. With no
file arguments at all, this is also the default when stdin is piped:

  echo "hello" | agevault encrypt - > secret.age
  echo "hello" | agevault encrypt --self > secret.age

Options:
  --self  Encrypt using identity (secret key) instead of recipients file
`)
	}
	self := fs.Bool("self", false, "Encrypt using identity (secret key) instead of recipients file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		if !stdinIsPipe() {
			fs.Usage()
			return fmt.Errorf("missing files")
		}
		return agevault.NewVault().Encrypt(*self, "-")
	}
	return agevault.NewVault().Encrypt(*self, fs.Args()...)
}

// stdinIsPipe reports whether stdin is a pipe/redirect rather than an
// interactive terminal, so a missing file argument can default to reading
// stdin without silently hanging when run interactively.
func stdinIsPipe() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

// ── decrypt ──────────────────────────────────────────────────────────────────

func cmdDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: agevault decrypt <file.age>...\n\nDecrypt .age file(s) to their original paths (strips .age suffix).\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("missing files")
	}
	return agevault.NewVault().Decrypt(fs.Args()...)
}

// ── cat ───────────────────────────────────────────────────────────────────────

func cmdCat(args []string) error {
	fs := flag.NewFlagSet("cat", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: agevault cat <file.age>...\n\nDecrypt .age file(s) and write plaintext to stdout.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("missing files")
	}
	return agevault.NewVault().Cat(fs.Args()...)
}

// ── reencrypt ─────────────────────────────────────────────────────────────────

func cmdReencrypt(args []string) error {
	fs := flag.NewFlagSet("reencrypt", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault reencrypt [--all] [<file.age>...]

Re-encrypt file(s) with the current recipients file.

Options:
  --all  Re-encrypt all *.age files tracked by Git
`)
	}
	all := fs.Bool("all", false, "Re-encrypt all *.age files tracked by Git")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return agevault.NewVault().Reencrypt(*all, fs.Args()...)
}

// ── rotate ────────────────────────────────────────────────────────────────────

func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault rotate [--new-key <file>] [--keep-old-key] [--kms-out] [--all] [<file.age>...]

Re-encrypt file(s) with a new key and update the recipients file.
If --new-key does not exist it will be generated.

Options:
  --new-key <file>  Path for the new key (default: ./age.key, or ./age.key.enc with --kms-out)
  --keep-old-key    Keep the old key in the recipients file alongside the new one
  --kms-out         Generate the new key in memory, KMS-encrypt it, and write the
                    ciphertext to --new-key. Requires KMS to be configured.
  --pq              Upgrade to a post-quantum hybrid ML-KEM-768+X25519 key.
                    Requires all existing recipients to also be hybrid (age1pq...).
                    If the current key is already hybrid, rotation preserves
                    the type automatically without this flag.
  --all             Rotate all *.age files tracked by Git
`)
	}
	newKey := fs.String("new-key", "", "Path for the new key file")
	keepOldKey := fs.Bool("keep-old-key", false, "Keep the old key in the recipients file alongside the new one")
	kmsOut := fs.Bool("kms-out", false, "Write KMS-encrypted new key instead of plaintext")
	pq := fs.Bool("pq", false, "Upgrade to a post-quantum hybrid ML-KEM-768+X25519 key (all recipients must be hybrid; auto-preserved if already hybrid)")
	all := fs.Bool("all", false, "Rotate all *.age files tracked by Git")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *newKey == "" {
		if *kmsOut {
			*newKey = "./age.key.enc"
		} else {
			*newKey = "./age.key"
		}
	}
	return agevault.NewVault().Rotate(*newKey, *keepOldKey, *all, *kmsOut, *pq, fs.Args()...)
}

// ── edit ──────────────────────────────────────────────────────────────────────

func cmdEdit(args []string) error {
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault edit [--self] <file>...

Decrypt, open in $EDITOR, and re-encrypt on save.

Options:
  --self  Re-encrypt using identity (secret key) instead of recipients file
`)
	}
	self := fs.Bool("self", false, "Re-encrypt using identity (secret key) instead of recipients file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("missing files")
	}
	return agevault.NewVault().Edit(*self, fs.Args()...)
}

// ── run ───────────────────────────────────────────────────────────────────────

const runHelp = `Usage: agevault run [--env <files>] [--decrypt <files>] [<env-files>...] -- <cmd> [args...]

Decrypt .age file(s) and execute a command, replacing the current process.

Options:
  --env FILES      Decrypt and load as environment variables (comma-separated)
  --decrypt FILES  Decrypt to their original paths without loading as env vars

Bare positional arguments before '--' are treated as env files (backwards compat).
Both options accept comma-separated file lists.
`

func cmdRun(args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "-help") {
		fmt.Fprint(os.Stderr, runHelp)
		return nil
	}
	// Parsed manually so we can support '--', comma-separated files, and
	// backwards-compat bare positional args (treated as env files).
	envFiles, decryptFiles, command, err := agevault.ParseRunArgs(args)
	if err != nil {
		return err
	}
	return agevault.NewVault().Run(envFiles, decryptFiles, command)
}

// ── agent / agent-run ────────────────────────────────────────────────────────

func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault agent [--socket <path>] [--env <files>] [--decrypt <files>]

Run a long-lived sidecar that resolves the identity and decrypts the given
files once at startup, then serves the decrypted content over a Unix socket
to any local client running 'agevault agent-run'. Runs in the foreground
until it receives SIGINT/SIGTERM, then removes the socket and exits.

--decrypt files are served keyed by basename only (directory and ".age"
suffix stripped), since the agent's own filesystem layout has no meaning to
a client in a different container. Two --decrypt files that reduce to the
same basename in the same secret are rejected at startup rather than
silently colliding.

Each --env/--decrypt entry may be tagged with a secret name via a "name="
prefix, e.g. --env db=db.env.age. Entries without a name belong to the
default (unnamed) secret. Entries sharing a name are merged into that
secret, so 'agevault agent-run' can later ask for one secret by name
instead of always getting everything the agent holds:

  agevault agent --socket ./a.sock \
    --env db=db.env.age,cert=cert.env.age \
    --decrypt db=db-ca.pem.age

Options:
  --socket <path>   Unix socket to listen on (default: $AGE_AGENT_SOCKET)
  --env FILES       Decrypt and serve as environment variables (comma-separated,
                    each entry optionally "name=file")
  --decrypt FILES   Decrypt and serve as file content, keyed by basename
                    (comma-separated, each entry optionally "name=file")
`)
	}
	socket := fs.String("socket", "", "Unix socket to listen on")
	env := fs.String("env", "", "Comma-separated .age files to serve as environment variables")
	decrypt := fs.String("decrypt", "", "Comma-separated .age files to serve as file content")
	if err := fs.Parse(args); err != nil {
		return err
	}

	v := agevault.NewVault()
	socketPath := *socket
	if socketPath == "" {
		socketPath = v.Config.AgentSocket
	}
	if socketPath == "" {
		fs.Usage()
		return fmt.Errorf("missing --socket (or set AGE_AGENT_SOCKET)")
	}

	envFiles := splitCommaList(*env)
	decryptFiles := splitCommaList(*decrypt)
	if len(envFiles) == 0 && len(decryptFiles) == 0 {
		fs.Usage()
		return fmt.Errorf("missing --env or --decrypt")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "[INFO] agevault agent listening on %s\n", socketPath)
	return v.RunAgent(ctx, socketPath, envFiles, decryptFiles)
}

func cmdAgentRun(args []string) error {
	fs := flag.NewFlagSet("agent-run", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault agent-run [--socket <path>] [--secret <names>] -- <cmd> [args...]

Connect to a running 'agevault agent', apply its decrypted env vars and files
to the current environment/directory, then exec the given command. Unlike
'agevault run', this needs no local identity, recipients, or KMS access —
only the agent does.

Decrypted files are written directly into the current directory, one file
per basename — there is no way to choose where they land; that is entirely
decided by the agent's own --decrypt configuration.

--secret selects which of the agent's named secrets to fetch (see
'agevault agent --help'). Omit it to get the agent's default (unnamed)
secret. Multiple comma-separated names are merged into one bundle, applied
together. Requesting an unknown name fails with the list of secrets the
agent actually serves.

Options:
  --socket <path>  Unix socket to connect to (default: $AGE_AGENT_SOCKET)
  --secret NAMES   Named secret(s) to fetch (comma-separated; default: the
                   agent's unnamed secret)
`)
	}
	socket := fs.String("socket", "", "Unix socket to connect to")
	secret := fs.String("secret", "", "Comma-separated named secret(s) to fetch")
	if err := fs.Parse(args); err != nil {
		return err
	}

	v := agevault.NewVault()
	socketPath := *socket
	if socketPath == "" {
		socketPath = v.Config.AgentSocket
	}
	if socketPath == "" {
		fs.Usage()
		return fmt.Errorf("missing --socket (or set AGE_AGENT_SOCKET)")
	}

	return v.AgentRun(socketPath, splitCommaList(*secret), fs.Args())
}

func cmdAgentPing(args []string) error {
	fs := flag.NewFlagSet("agent-ping", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault agent-ping [--socket <path>]

Check whether an 'agevault agent' is listening on the given Unix socket.
Exits 0 if a connection succeeds, non-zero otherwise — nothing is requested
or applied, so this is safe to run repeatedly.

Intended as a container HEALTHCHECK / readiness probe. The agent only opens
its socket after its one-time identity/KMS resolution has already
succeeded, so a passing ping means the agent is actually ready to serve —
not just that its container has started. Since the published agevault image
has no shell, use this instead of a shell-based healthcheck:

  healthcheck:
    test: ["CMD", "agevault", "agent-ping", "--socket", "/run/agevault-agent/agent.sock"]

Options:
  --socket <path>  Unix socket to check (default: $AGE_AGENT_SOCKET)
`)
	}
	socket := fs.String("socket", "", "Unix socket to check")
	if err := fs.Parse(args); err != nil {
		return err
	}

	v := agevault.NewVault()
	socketPath := *socket
	if socketPath == "" {
		socketPath = v.Config.AgentSocket
	}
	if socketPath == "" {
		fs.Usage()
		return fmt.Errorf("missing --socket (or set AGE_AGENT_SOCKET)")
	}

	return agevault.PingAgent(socketPath)
}

// splitCommaList splits s on commas, trimming whitespace and dropping empty parts.
func splitCommaList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// ── key-* ─────────────────────────────────────────────────────────────────────

func cmdKeyAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing users")
	}
	return agevault.NewVault().KeyAdd(args...)
}

func cmdKeyGet(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected exactly one username")
	}
	key, err := agevault.NewVault().KeyGet(args[0])
	if err != nil {
		return err
	}
	fmt.Print(key)
	return nil
}

func cmdKeyReadd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing users")
	}
	return agevault.NewVault().KeyReadd(args...)
}

// ── init ──────────────────────────────────────────────────────────────────────

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault init [--pq]

Generate a new age key pair and write it to AGE_SECRET_KEY_FILE
(default: ~/.age/age.key). The public key is also written to a .pub
file alongside it. Fails if the key file already exists.

Options:
  --pq  Generate a post-quantum hybrid ML-KEM-768+X25519 key
`)
	}
	pq := fs.Bool("pq", false, "Generate a post-quantum hybrid ML-KEM-768+X25519 key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return agevault.NewVault().Init(*pq)
}

// ── keygen ────────────────────────────────────────────────────────────────────

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault keygen [-o <file>] [--pq] [-y <file>]

Generate a new age key pair and write it in age-keygen format.

Options:
  -o <file>  Write private key to file instead of stdout
  --pq       Generate a post-quantum hybrid ML-KEM-768+X25519 key
  -y <file>  Print the public key of an existing private key file
`)
	}
	outPath := fs.String("o", "", "Write private key to file instead of stdout")
	pq := fs.Bool("pq", false, "Generate a post-quantum hybrid ML-KEM-768+X25519 key")
	convertY := fs.String("y", "", "Print the public key of an existing private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *convertY != "" {
		pub, err := agevault.PublicKeyFromFile(*convertY)
		if err != nil {
			return err
		}
		fmt.Println(pub)
		return nil
	}

	if *outPath != "" {
		var pub string
		if *pq {
			id, err := agevault.GenerateHybridIdentityToFile(*outPath)
			if err != nil {
				return err
			}
			pub = id.Recipient().String()
		} else {
			id, err := agevault.GenerateIdentity(*outPath)
			if err != nil {
				return err
			}
			pub = id.Recipient().String()
		}
		fmt.Fprintf(os.Stderr, "Public key: %s\n", pub)
		return nil
	}

	_, err := agevault.KeygenToWriter(*pq, os.Stdout)
	return err
}

// ── pubkey ────────────────────────────────────────────────────────────────────

func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault pubkey

Print the public key of the currently configured identity, resolved the
same way any other command resolves it: KMS (if configured) > AGE_SECRET_KEY
> AGE_SECRET_KEY_FILE. Unlike 'keygen -y <file>', which only works on a
local private key file, this also works when the identity is KMS-protected
— e.g. to derive the recipient for 'agevault encrypt' without ever touching
the plaintext private key yourself.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := agevault.NewVault().GetPublicKey()
	if err != nil {
		return err
	}
	fmt.Println(pub)
	return nil
}

// ── completion ────────────────────────────────────────────────────────────────

func cmdCompletion(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected shell name: bash or zsh")
	}
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	default:
		return fmt.Errorf("unsupported shell %q (use bash or zsh)", args[0])
	}
	return nil
}

// ── git-setup ─────────────────────────────────────────────────────────────────

func cmdGitSetup(args []string) error {
	fs := flag.NewFlagSet("git-setup", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: agevault git-setup [--local|--global|--system]

Configure Git integration so 'git diff' shows decrypted *.age content.

Sets diff.agevault.textconv = "agevault cat" in git config and adds
"**/*.age diff=agevault" to .gitattributes at the repository root.

Options:
  --scope <value>  git config scope: --local (default), --global, or --system
`)
	}
	// Accept scope as either a positional arg (shell-script parity) or a flag.
	scope := fs.String("scope", "", "git config scope (--local, --global, --system); default: --local")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Positional arg overrides --scope flag.
	if fs.NArg() > 0 {
		*scope = fs.Arg(0)
	}
	return agevault.GitSetup(*scope)
}

// ── help text ─────────────────────────────────────────────────────────────────

const helpText = `Usage: agevault <command> [options] [files...]

Commands:
  encrypt       Encrypt file(s); "-" reads stdin and writes ciphertext to stdout
                  --self            Encrypt using identity instead of recipients file
  decrypt       Decrypt .age file(s)
  cat           Decrypt and print to stdout
  reencrypt     Re-encrypt file(s) with updated recipients file
                  --all             Re-encrypt all *.age files tracked by Git
  rotate        Re-encrypt file(s) with a new key (and update recipients file)
                  --new-key <file>  Path to new age private key (default: ./age.key)
                  --keep-old-key    Keep old key in recipients (both can decrypt)
                  --all             Rotate all *.age files tracked by Git
  edit          Edit encrypted file(s) securely in $EDITOR
  run           Decrypt file(s) into environment, then run command
                  --env FILES       Load as environment variables (comma-separated)
                  --decrypt FILES   Decrypt to disk without loading as env vars
  agent         Run a sidecar that decrypts file(s) once and serves them over a socket
                  --socket <path>   Unix socket to listen on (default: $AGE_AGENT_SOCKET)
                  --env FILES       Serve as environment variables (comma-separated;
                                    entries may be "name=file" to name a secret)
                  --decrypt FILES   Serve as file content (comma-separated;
                                    entries may be "name=file" to name a secret)
  agent-run     Fetch decrypted content from 'agevault agent', then run command
                  --socket <path>   Unix socket to connect to (default: $AGE_AGENT_SOCKET)
                  --secret NAMES    Named secret(s) to fetch (comma-separated;
                                    default: the agent's unnamed secret)
  agent-ping    Check whether 'agevault agent' is listening (for healthchecks)
                  --socket <path>   Unix socket to check (default: $AGE_AGENT_SOCKET)
  key-add       Add public key(s) from AGE_KEY_SERVER to recipients file
  key-get       Fetch a public key from AGE_KEY_SERVER
  key-readd     Reset and re-add public key(s) from AGE_KEY_SERVER
  init          Generate a new age key pair at AGE_SECRET_KEY_FILE (~/.age/age.key)
                  --pq              Generate a post-quantum hybrid ML-KEM-768+X25519 key
  keygen        Generate a new age key pair (replaces age-keygen)
                  -o <file>         Write private key to file instead of stdout
                  --pq              Generate a post-quantum hybrid ML-KEM-768+X25519 key
                  -y <file>         Print the public key of an existing private key file
  pubkey        Print the public key of the currently configured identity
                                    (works for KMS-protected identities too)
  completion    Generate shell completion script (bash|zsh)
  git-setup     Configure Git integration for agevault diff viewing
  version       Print version
  help          Show this help

Environment:
  AGE_SECRET_KEY            Inline private key string (takes precedence)
  AGE_SECRET_KEY_FILE       Path to private key file (default: ~/.age/age.key)
  AGE_RECIPIENTS            Comma-separated recipients (takes precedence)
  AGE_RECIPIENTS_FILE       Recipients file (default: .age.txt)
  AGE_AGENT_SOCKET          Unix socket path for agent / agent-run
  AGE_KEY_SERVER            Required for key-add / key-get / key-readd
  AGE_PUBKEY_EXT            Extension for public keys on key server (default: pub)
  AGE_KMS_PROVIDER          Force KMS provider: aws or gcp (required if both keys are set)
  AGE_AWS_KMS_ENCRYPTED_KEY Base64 AWS KMS ciphertext of age private key
  AGE_GCP_KMS_ENCRYPTED_KEY Base64 GCP KMS ciphertext of age private key
  AWS_KMS_KEY_ID            AWS KMS key ID / ARN / alias (optional)
  AWS_REGION                AWS region (falls back to AWS_DEFAULT_REGION)
  GCP_KMS_KEY_NAME          GCP KMS key resource name (projects/*/locations/*/keyRings/*/cryptoKeys/*)

Run 'agevault <command> --help' for per-command usage.
`
