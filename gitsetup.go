package agevault

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitSetup configures Git integration so that `git diff` can show decrypted
// content of *.age files via `agevault cat`.
//
// scope must be one of "--local" (default), "--global", or "--system".
// It:
//   - Sets diff.agevault.textconv = "agevault cat" in git config
//   - Adds/updates "**/*.age diff=agevault" in .gitattributes at the repo root
func GitSetup(scope string) error {
	if scope == "" {
		scope = "--local"
	}
	switch scope {
	case "--global", "--system", "--local":
	default:
		return fmt.Errorf("unknown option: %s", scope)
	}

	if err := exec.Command("git", "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		return fmt.Errorf("cannot access Git repository")
	}

	rootOut, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return fmt.Errorf("get git repo root: %w", err)
	}
	repoRoot := strings.TrimSpace(string(rootOut))

	// Configure diff.agevault.textconv.
	textconvCmd := "agevault cat"
	currentOut, _ := exec.Command("git", "config", scope, "--get", "diff.agevault.textconv").Output()
	current := strings.TrimSpace(string(currentOut))
	scopeName := strings.TrimPrefix(scope, "--")
	if current != textconvCmd {
		if err := exec.Command("git", "config", scope, "diff.agevault.textconv", textconvCmd).Run(); err != nil {
			return fmt.Errorf("set git config: %w", err)
		}
		fmt.Printf("configured diff.agevault.textconv in %s.\n", scopeName)
	} else {
		fmt.Printf("already set diff.agevault.textconv in %s.\n", scopeName)
	}

	// Update .gitattributes.
	attrLine := "**/*.age diff=agevault"
	attrFile := filepath.Join(repoRoot, ".gitattributes")

	attrContent, readErr := os.ReadFile(attrFile)
	if readErr != nil && !os.IsNotExist(readErr) {
		return fmt.Errorf("read .gitattributes: %w", readErr)
	}

	if os.IsNotExist(readErr) {
		if err := os.WriteFile(attrFile, []byte(attrLine+"\n"), 0644); err != nil {
			return fmt.Errorf("create .gitattributes: %w", err)
		}
		fmt.Println("created .gitattributes at the Git repository root.")
		return nil
	}

	// File exists – scan for the pattern and update or append.
	lines := strings.Split(strings.TrimRight(string(attrContent), "\n"), "\n")
	found := false
	changed := false
	for i, line := range lines {
		if strings.HasPrefix(line, "**/*.age diff=") {
			found = true
			if line != attrLine {
				lines[i] = attrLine
				changed = true
			}
			break
		}
	}

	if !found {
		lines = append(lines, attrLine)
		changed = true
		fmt.Println("configured .gitattributes at the Git repository root.")
	} else if changed {
		fmt.Println("updated .gitattributes at the Git repository root.")
	} else {
		fmt.Println("already set .gitattributes at the Git repository root.")
	}

	if changed {
		newContent := strings.Join(lines, "\n") + "\n"
		return os.WriteFile(attrFile, []byte(newContent), 0644)
	}
	return nil
}
