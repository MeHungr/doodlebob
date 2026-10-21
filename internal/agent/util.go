// Includes utility functions
package agent

import (
	"log"
	"net"
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
