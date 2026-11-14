// Command agevault-agent is the ssh-agent counterpart for age identities: it
// holds unlocked private keys in memory so agevault can decrypt without the
// key sitting in plaintext on disk and without a passphrase prompt on every
// command.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	agevault "github.com/zachcheung/agevault-go"
)

// version is set at build time via -ldflags "-X main.version=v1.2.3".
var version = "HEAD"

const helpText = `Usage: agevault-agent <command> [options]

Hold unlocked age private keys in memory and decrypt on behalf of agevault,
like ssh-agent does for ssh. Private keys never leave the agent.

Commands:
  serve       Run the agent (in the foreground; start it as a user service)
  add         Unlock a key file and add it to the agent
                -t <duration>   Forget the key after this long (e.g. 8h)
                [<keyfile>]     Defaults to AGE_SECRET_KEY_FILE (~/.age/age.key)
  list        List the public keys of the keys held by the agent
  clear       Remove all keys from the agent
  completion  Generate shell completion script (bash|zsh)
  version     Print the version

serve, add, list and clear take --socket <path> (default: $AGE_KEY_AGENT_SOCKET).

agevault uses the agent whenever AGE_KEY_AGENT_SOCKET is set and the agent
holds a key; otherwise it falls back to AGE_SECRET_KEY_FILE as usual.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stdout, helpText)
		os.Exit(0)
	}

	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "add":
		err = cmdAdd(args)
	case "list":
		err = cmdList(args)
	case "clear":
		err = cmdClear(args)
	case "completion":
		err = cmdCompletion(args)
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, helpText)
	default:
		fmt.Fprintf(os.Stderr, "agevault-agent: unknown command %q\n\n%s", cmd, helpText)
		os.Exit(1)
	}

	if err != nil && err != flag.ErrHelp {
		fmt.Fprintf(os.Stderr, "agevault-agent %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// newFlagSet returns a FlagSet with the shared --socket flag and a resolver
// for it that falls back to AGE_KEY_AGENT_SOCKET.
func newFlagSet(name, usage string) (*flag.FlagSet, func() (string, error)) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	socket := fs.String("socket", "", "Unix socket path")
	resolve := func() (string, error) {
		if *socket != "" {
			return *socket, nil
		}
		if s := os.Getenv("AGE_KEY_AGENT_SOCKET"); s != "" {
			return s, nil
		}
		return "", fmt.Errorf("missing --socket (or set AGE_KEY_AGENT_SOCKET)")
	}
	return fs, resolve
}

func setLogLevel() {
	var level slog.Level
	if s := os.Getenv("LOG_LEVEL"); s != "" {
		if err := level.UnmarshalText([]byte(s)); err != nil {
			slog.Warn("invalid LOG_LEVEL, using info", "value", s)
			return
		}
	}
	slog.SetLogLoggerLevel(level)
}

func cmdServe(args []string) error {
	fs, socket := newFlagSet("serve", `Usage: agevault-agent serve [--socket <path>]

Run the agent in the foreground until interrupted. It starts with no keys;
add one with 'agevault-agent add'. Keys live only in this process's memory
and are gone when it exits.

The socket is created with mode 0600. On Linux the process is also marked
non-dumpable, so other processes of the same user cannot read its memory.

Options:
  --socket <path>  Unix socket to listen on (default: $AGE_KEY_AGENT_SOCKET)

Environment:
  LOG_LEVEL        debug, info (default), warn or error
`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	socketPath, err := socket()
	if err != nil {
		return err
	}
	setLogLevel()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return new(agevault.KeyAgent).Serve(ctx, socketPath)
}

func cmdAdd(args []string) error {
	fs, socket := newFlagSet("add", `Usage: agevault-agent add [--socket <path>] [-t <duration>] [<keyfile>]

Unlock a private key file — asking for its passphrase if it is protected —
and add it to the running agent. Defaults to AGE_SECRET_KEY_FILE
(~/.age/age.key). Adding a key the agent already holds refreshes its lifetime.

Options:
  --socket <path>  Unix socket of the agent (default: $AGE_KEY_AGENT_SOCKET)
  -t <duration>    Forget the key after this long, e.g. 30m, 8h (default: keep
                   it until the agent exits)
`)
	lifetime := fs.Duration("t", 0, "Forget the key after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("too many arguments")
	}
	if *lifetime < 0 || (*lifetime > 0 && *lifetime < time.Second) {
		return fmt.Errorf("-t must be at least 1s")
	}
	socketPath, err := socket()
	if err != nil {
		return err
	}

	v := agevault.NewVault()
	keyFile := v.Config.SecretKeyFile
	if fs.NArg() == 1 {
		keyFile = fs.Arg(0)
	}
	added, err := v.AddKeyToAgent(socketPath, keyFile, *lifetime)
	if err != nil {
		return err
	}
	suffix := ""
	if *lifetime > 0 {
		suffix = fmt.Sprintf(" (lifetime %s)", *lifetime)
	}
	fmt.Fprintf(os.Stderr, "Key added: %s%s\n", strings.Join(added, ", "), suffix)
	return nil
}

func cmdList(args []string) error {
	fs, socket := newFlagSet("list", `Usage: agevault-agent list [--socket <path>]

Print the public key of every key held by the agent, one per line, in the
order they were added. Exits non-zero if the agent has no keys.

Options:
  --socket <path>  Unix socket of the agent (default: $AGE_KEY_AGENT_SOCKET)
`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	socketPath, err := socket()
	if err != nil {
		return err
	}
	keys, err := agevault.KeyAgentList(socketPath)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("the agent has no keys")
	}
	for _, k := range keys {
		if k.Expires != nil {
			fmt.Printf("%s\t(expires in %s)\n", k.PublicKey, time.Until(*k.Expires).Round(time.Second))
		} else {
			fmt.Println(k.PublicKey)
		}
	}
	return nil
}

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

func cmdClear(args []string) error {
	fs, socket := newFlagSet("clear", `Usage: agevault-agent clear [--socket <path>]

Remove all keys from the agent. The agent keeps running.

Options:
  --socket <path>  Unix socket of the agent (default: $AGE_KEY_AGENT_SOCKET)
`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	socketPath, err := socket()
	if err != nil {
		return err
	}
	if err := agevault.KeyAgentClear(socketPath); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "All keys removed.")
	return nil
}
