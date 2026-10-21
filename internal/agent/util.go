// Includes utility functions
package agent

import (
	"log"
	"net"

	"github.com/google/gopacket/pcap"
)

// localIP determines the localIP of the host by opening a UDP connection
// This does not send any packets, since UDP is connectionless
// It simply forces the host to decide on an IP address
func localIP() (localAddr *net.UDPAddr) {
	conn, err := net.Dial("udp", "8.8.8.8:80") // Open the connection
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close() // Close the connection when this function returns

	localAddr = conn.LocalAddr().(*net.UDPAddr)

	return
}

// getNetworkInterface returns the network interface associated with an IP address
func getNetworkInterface(ipAddr net.IP) *pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Enumerate interfaces
	for _, device := range devices {
		// Enumerate IP addresses associated with each interface
		for _, address := range device.Addresses {
			// Check if IP is equal to ipAddr parameter
			if address.IP != nil && address.IP.Equal(ipAddr) {
				return &device // Return the interface associated wtih ipAddr
			}
		}
	}

	return nil
}
