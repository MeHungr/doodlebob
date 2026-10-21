// Determines the shell to use on UNIX systems
//go:build linux || darwin || freebsd

package executor

import "os"

const (
	bash = "/bin/bash"
	sh   = "/bin/sh"
)

// getShell returns the shell used for this system
func getShell() (shell string) {
	shell = sh
	if _, err := os.Stat(bash); err == nil {
		shell = bash
	}
	return
}

// getShellArgs returns the arguments for command execution with the shell
func getShellArgs(command string) []string {
	return []string{"-c", command}
}
