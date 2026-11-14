//go:build !linux

package agevault

// hardenProcess is a no-op on platforms without PR_SET_DUMPABLE.
func hardenProcess() {}
