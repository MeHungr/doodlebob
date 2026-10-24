// Contains logic for sending a packet using a pcap interface
package agent

import (
	"fmt"
	"net"

	"github.com/MeHungr/doodlebob/internal/network"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func sendPacket(
	device *pcap.Interface,
	srcMAC, dstMAC net.HardwareAddr,
	etherType layers.EthernetType, srcIP, dstIP net.IP,
	srcPort, dstPort int,
	l4proto network.L4Proto,
	packetData []byte,
) (
	error,
) {
	// Open a handle to pcap interface
	handle, err := pcap.OpenLive(device.Name, 65535, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening pcap device %s: %w", device.Name, err)
	}
	
	// Create packet
	packet, err := network.CreatePacket(srcMAC, dstMAC, etherType, srcIP, dstIP, srcPort, dstPort, l4proto, packetData)
	if err != nil {
		return fmt.Errorf("creating packet: %w", err)
	}

	// Send packet
	if err := handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("writing raw packet data to wire: %w", err)
	}

	// Success
	return nil
}
