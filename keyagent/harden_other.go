//go:build !linux

package keyagent

// hardenProcess is a no-op on platforms without PR_SET_DUMPABLE.
func hardenProcess() {}
