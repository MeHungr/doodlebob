// Contains logic for egress traffic in the pcapconn interface
package pcapconn

import (
	"context"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

// StartEgressWorker drains packets from gVisor, wraps them in Ethernet frames, and writes to PCAP.
func StartEgressWorker(ctx context.Context, linkEP *channel.Endpoint, handle *pcap.Handle, srcMAC, dstMAC net.HardwareAddr) error {
	for {
		pkt := linkEP.ReadContext(ctx)
		if pkt == nil {
			return nil
		}

		// Flatten gVisor's fragmented packet buffer into a flat slice
		// [][]byte -> []byte
		gvisorBytes := make([]byte, 0, pkt.Size())
		for _, view := range pkt.AsSlices() {
			gvisorBytes = append(gvisorBytes, view...)
		}

		pkt.DecRef()

		// Construct raw Ethernet framework
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

		ethLayer := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}

		err := gopacket.SerializeLayers(buf, opts, ethLayer, gopacket.Payload(gvisorBytes))
		if err == nil {
			// Write the complete frame straight out onto the physical wire
			if err := handle.WritePacketData(buf.Bytes()); err != nil {
				return fmt.Errorf("write Ethernet frame: %w", err)
			}
		} else {
			return fmt.Errorf("serialize Ethernet frame: %w", err)
		}
	}
}
