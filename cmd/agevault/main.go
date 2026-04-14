package main

import (
	"flag"
	"fmt"
	"os"

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
	case "key-add":
		err = cmdKeyAdd(args)
	case "key-get":
		err = cmdKeyGet(args)
	case "key-readd":
		err = cmdKeyReadd(args)
	case "completion":
		err = cmdCompletion(args)
	case "git-setup":
		err = cmdGitSetup(args)
	case "version", "--version", "-version", "-v":
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

Options:
  --self  Encrypt using identity (secret key) instead of recipients file
`)
	}
	self := fs.Bool("self", false, "Encrypt using identity (secret key) instead of recipients file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("missing files")
	}
	return agevault.NewVault().Encrypt(*self, fs.Args()...)
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
		fmt.Fprint(os.Stderr, `Usage: agevault rotate [--new-key <file>] [--keep-old-key] [--all] [<file.age>...]

Re-encrypt file(s) with a new key and update the recipients file.
If --new-key does not exist it will be generated.

Options:
  --new-key <file>  Path to the new age private key (default: ./age.key)
  --keep-old-key    Keep the old key in the recipients file alongside the new one
  --all             Rotate all *.age files tracked by Git
`)
	}
	newKey := fs.String("new-key", "./age.key", "Path to the new age private key (generated if absent)")
	keepOldKey := fs.Bool("keep-old-key", false, "Keep the old key in the recipients file alongside the new one")
	all := fs.Bool("all", false, "Rotate all *.age files tracked by Git")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return agevault.NewVault().Rotate(*newKey, *keepOldKey, *all, fs.Args()...)
}

// ── edit ──────────────────────────────────────────────────────────────────────

func cmdEdit(args []string) error {
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: agevault edit <file>...\n\nDecrypt, open in $EDITOR, and re-encrypt on save.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("missing files")
	}
	return agevault.NewVault().Edit(fs.Args()...)
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
  encrypt       Encrypt file(s)
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
  key-add       Add public key(s) from AGE_KEY_SERVER to recipients file
  key-get       Fetch a public key from AGE_KEY_SERVER
  key-readd     Reset and re-add public key(s) from AGE_KEY_SERVER
  completion    Generate shell completion script (bash|zsh)
  git-setup     Configure Git integration for agevault diff viewing
  version       Print version
  help          Show this help

Environment:
  AGE_SECRET_KEY        Inline private key string (takes precedence)
  AGE_SECRET_KEY_FILE   Path to private key file (default: ~/.age/age.key)
  AGE_RECIPIENTS        Comma-separated recipients (takes precedence)
  AGE_RECIPIENTS_FILE   Recipients file (default: .age.txt)
  AGE_KEY_SERVER        Required for key-add / key-get / key-readd
  AGE_PUBKEY_EXT        Extension for public keys on key server (default: pub)

Run 'agevault <command> --help' for per-command usage.
`
