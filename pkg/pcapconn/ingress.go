package pcapconn

import (
	"context"
	"fmt"
	"log"

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
			log.Printf("pcapconn ingress: dropping truncated packet captured=%d original=%d", info.CaptureLength, info.Length)
			continue
		}
		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)
		// Extract raw IPv4 packet layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			if tcp.SYN || tcp.RST || tcp.FIN {
				log.Printf("pcapconn ingress: %s:%d -> %s:%d SYN=%t ACK=%t RST=%t FIN=%t seq=%d ack=%d checksum=0x%04x bytes=%d",
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
					tcp.SYN, tcp.ACK, tcp.RST, tcp.FIN, tcp.Seq, tcp.Ack, tcp.Checksum, len(ip.Contents)+len(ip.Payload))
			}
		}
		if decodeErr := packet.ErrorLayer(); decodeErr != nil {
			log.Printf("pcapconn ingress: packet decode error: %v", decodeErr.Error())
		}

		// Inject raw IP network bytes directly into gVisor's link layer handler
		pktBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append(append([]byte(nil), ip.Contents...), ip.Payload...)),
		})

		linkEP.InjectInbound(ipv4.ProtocolNumber, pktBuffer)
		pktBuffer.DecRef()
	}
	return nil
}
