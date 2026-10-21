// Determines the shell to use on Windows systems
//go:build windows

package executor

const (
	powershell = "powershell.exe"
)

// getShell returns the shell used for this system
func getShell() (shell string) {
	return powershell
}

// getShellArgs returns the arguments for command execution with the shell
func getShellArgs(command string) []string {
	return []string{"-WindowStyle", "Hidden", "-Command", command}
}
