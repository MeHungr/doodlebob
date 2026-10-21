// The main logic for the packet capture done by the listening agent
package agent

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

// listInterfaces lists available interfaces for packet capture
func listInterfaces() ([]pcap.Interface, error) {
	// Enumerates interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find interfaces: %w", err)
	}

	count := 1
	// Prints interfaces in a human readable format
	for _, device := range devices {
		fmt.Printf("%d.  %s: %s\n", count, device.Name, device.Description)

		for _, address := range device.Addresses {
			fmt.Printf("  IP: %s\n", address.IP)
		}
		count++
	}

	return devices, err
}

// ChooseInterface asks for user input to choose an interface to capture on
func ChooseInterface() (*pcap.Interface, error) {
	var deviceNumber int

	// List interfaces
	devices, err := listInterfaces()
	if err != nil {
		return nil, fmt.Errorf("choose interface: %w", err)
	}

	// Query user for interface selection
	fmt.Print("Select an interface: ")
	if _, err := fmt.Scan(&deviceNumber); err != nil {
		return nil, fmt.Errorf("error handling input: %w", err)
	}

	// Change from 1 indexed to 0 indexed and return the selected interface
	deviceIndex := deviceNumber - 1
	device := devices[deviceIndex]

	return &device, nil
}

// ListenDefaultInterface calls Listen() using the default network interface
func ListenDefaultInterface() (*pcap.Handle, error) {
	handle, err := Listen(getNetworkInterface(localIP().IP))
	if err != nil {
		return nil, fmt.Errorf("default interface: %w", err)
	}
	return handle, nil
}

// Listen listens for traffic on the selected interface
func Listen(device *pcap.Interface) (*pcap.Handle, error) {
	// Opens a packet capture on the specified interface
	handle, err := pcap.OpenLive(
		device.Name,       // Name of the interface
		65536,             // Snapshot length
		false,             // Promiscuous mode
		pcap.BlockForever, // Timeout length
	)
	if err != nil {
		return nil, fmt.Errorf("open interface %q: %w", device.Name, err)
	}

	return handle, nil
}
