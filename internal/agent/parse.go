// This contains the packet parsing logic for the listening agent
package agent

import (
	"bytes"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// hasMagicHeader checks to see if incoming packets have the magic header as their payload
func hasMagicHeader(payload []byte) bool {
	var magicHeader = []byte{0x44, 0x4F, 0x4F, 0x44, 0x4C, 0x45} // "DOODLE"
	return len(payload) >= len(magicHeader) && bytes.Equal(payload[:len(magicHeader)], magicHeader) // Checks for match
}

// ReadPackets reads the packets from the open pcap handle
func ReadPackets(handle *pcap.Handle) error {
	source := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	// Read packet application layer payloads and print them
	for packet := range source.Packets() {
		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			continue
		}

		payload := appLayer.Payload()
		if hasMagicHeader(payload) {
			fmt.Printf("Application payload: %x\n", payload)
		}
	}

	return nil
}
