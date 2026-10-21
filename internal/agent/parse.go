// This contains the packet parsing logic for the listening agent
package agent

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ReadPackets reads the packets from the open pcap handle
func ReadPackets(handle *pcap.Handle) error {
	source := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	// Read packets and print length
	for packet := range source.Packets() {
		fmt.Printf("Captured packet: %d bytes\n", len(packet.Data()))

		if errLayer := packet.ErrorLayer(); errLayer != nil {
			log.Printf("Packet decoding error: %v", errLayer.Error())
		}
	}

	return nil
}
