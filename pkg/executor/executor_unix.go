// Contains logic for executing commands on UNIX systems
//go:build linux || darwin || freebsd

package executor

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// ExecuteCommand takes a command and optional timeout value, then executes the command
// It returns the output and return code of the command
// Set timeout to nil for no timeout
func ExecuteCommand(command string, timeout *time.Duration) (output string, returnCode string) {
	// Initialize an empty context and command
	var (
		cmd    *exec.Cmd
		ctx    context.Context
		cancel context.CancelFunc
	)

	// Default to sh, then attempt to use bash
	shell := "/bin/sh"
	if _, err := os.Stat("/bin/bash"); err == nil {
		shell = "/bin/bash"
	}

	// If the command has a timeout duration, cancel the command's execution after that duration
	if timeout != nil {
		ctx, cancel = context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, shell, "-c", command)
	} else { // Otherwise, execute the command with no timeout
		cmd = exec.Command(shell, "-c", command)
	}

	// Run the command and capture stdout + stderr
	out, err := cmd.CombinedOutput()
	output = string(out)

	// Check if the command timed out
	if timeout != nil && ctx.Err() == context.DeadlineExceeded {
		returnCode = "command timed out"
		return
	}

	// If the command failed for another reason
	if err != nil {
		if cmd.ProcessState != nil {
			returnCode = strconv.Itoa(cmd.ProcessState.ExitCode())
		} else {
			returnCode = "command failed to start"
		}
		return
	}

	// Success!
	returnCode = strconv.Itoa(cmd.ProcessState.ExitCode())
	return // output, returnCode
}
