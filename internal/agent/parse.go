// This contains the packet parsing logic for the listening agent
package agent

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

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
		fmt.Printf("Application payload: %x\n", payload)
	}

	return nil
}
