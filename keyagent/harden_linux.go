package keyagent

import "golang.org/x/sys/unix"

// hardenProcess marks the key agent process non-dumpable, so other processes
// of the same user cannot ptrace it or read its memory through /proc, and it
// leaves no core dump — the same protection ssh-agent applies to itself.
func hardenProcess() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
