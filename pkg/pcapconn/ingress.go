package pcapconn

import (
	"context"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// StartIngressWorker continuously sniffs packets allowed through by the BPF filter and forwards them to gVisor.
func StartIngressWorker(ctx context.Context, handle *pcap.Handle, linkEP *channel.Endpoint) error {
	for ctx.Err() == nil {
		data, info, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			return fmt.Errorf("capture packet: %w", err)
		}
		if info.CaptureLength < info.Length {
			continue
		}
		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)
		// Extract raw IPv4 packet layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// Inject raw IP network bytes directly into gVisor's link layer handler
		pktBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append(append([]byte(nil), ip.Contents...), ip.Payload...)),
		})

		linkEP.InjectInbound(ipv4.ProtocolNumber, pktBuffer)
		pktBuffer.DecRef()
	}
	return nil
}
