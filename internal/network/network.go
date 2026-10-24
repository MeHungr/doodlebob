// Includes utility functions
package network

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket/pcap"
	"github.com/libp2p/go-netroute"
)

// LocalIP determines the localIP of the host by opening a UDP connection
// This does not send any packets, since UDP is connectionless
// It simply forces the host to decide on an IP address
func LocalIP() (localAddr *net.UDPAddr) {
	conn, err := net.Dial("udp", "8.8.8.8:80") // Open the connection
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close() // Close the connection when this function returns

	localAddr = conn.LocalAddr().(*net.UDPAddr)

	return
}

// GetNetworkInterface returns the network interface associated with an IP address
func GetNetworkInterface(ipAddr net.IP) (*pcap.Interface, error) {
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
				return &device, nil // Return the interface associated wtih ipAddr
			}
		}
	}

	return nil, fmt.Errorf("no pcap device found for IP %s", ipAddr)
}

// ResolveNextHopMAC resolves the next hop's MAC address from the destination IP
func ResolveNextHopMAC(
	ctx context.Context,
	dstIP net.IP,
) (net.HardwareAddr, error) {
	// Find outgoing interface and gateway
	iface, gateway, srcIP, err := LookupRoute(dstIP)
	if err != nil {
		return nil, err
	}

	// Determine the next-hop IP
	// Checks that the gateway is routed to, and that it is not a generic address
	nextHop := dstIP
	if gateway != nil && !gateway.IsUnspecified() {
		nextHop = gateway
	}

	// Find the pcap interface corresponding to the route
	device, err := GetNetworkInterface(srcIP)
	if err != nil {
		return nil, err
	}

	// Resolve next-hop MAC using ARP
	return ResolveARP(
		ctx,
		device,
		iface.HardwareAddr,
		srcIP,
		nextHop,
	)
}

// LookupRoute determines how the OS would route a packet to dstIP
//
// gateway == nil means the destination is directly reachable on the selected interface
func LookupRoute(
	dstIP net.IP,
) (
	device *net.Interface,
	gateway net.IP,
	srcIP net.IP,
	err error,
) {
	// Ensure dstIP is IPv4
	if dstIP.To4() == nil {
		err = fmt.Errorf("LookupRoute requires IPv4")
		return
	}

	// Create a new router object to determine route
	router, e := netroute.New()
	if e != nil {
		err = fmt.Errorf("create router: %w", e)
		return
	}

	// Determine route to dstIP
	device, gateway, srcIP, e = router.Route(dstIP)
	if e != nil {
		err = fmt.Errorf("rout to %s: %w", dstIP, err)
		return
	}

	// Ensure an interface was  found
	if device == nil {
		err = fmt.Errorf("no interface found for %s", dstIP)
	}

	// Ensure that a source address was found
	if srcIP == nil || srcIP.To4() == nil {
		err = fmt.Errorf("no IPv4 source address for %s", dstIP)
		return
	}

	// Return all named variables
	return
}

// equalMAC determines whether 2 MAC addresses are equal
func equalMAC(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
