// Contains logic for deploying a pcapconn interface
package pcapconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/MeHungr/doodlebob/pkg/isolator"
	"github.com/MeHungr/doodlebob/pkg/network"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Dial establishes an in-memory gVisor network stack over a raw PCAP handle
// and dials out to a remote destination using the host's real IP and identity.
// Requires Ethernet and a platform-supported packet capture driver with capture
// and injection privileges. The caller must isolate this TCP flow from host-kernel
// RST responses using platform-specific network configuration.
// Close releases the stack, capture handle, and workers.
// ctx controls dialing; the returned connection lives until Close is called.
func Dial(ctx context.Context, device *pcap.Interface, srcPort int, targetIP string, targetPort int) (result net.Conn, dialErr error) {
	if device == nil || device.Name == "" {
		return nil, fmt.Errorf("a capture device is required")
	}
	remoteIPBytes := net.ParseIP(targetIP).To4()
	if remoteIPBytes == nil || remoteIPBytes.IsUnspecified() || remoteIPBytes.IsMulticast() {
		return nil, fmt.Errorf("target must be a unicast IPv4 address")
	}
	if srcPort < 1 || srcPort > 65535 || targetPort < 1 || targetPort > 65535 {
		return nil, fmt.Errorf("ports must be between 1 and 65535")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Get the default interface as a net.Interface
	iface, gateway, hostIPv4, err := network.LookupRoute(remoteIPBytes)
	if err != nil {
		return nil, fmt.Errorf("lookup target route: %w", err)
	}
	if !deviceMatchesRoute(device, iface, hostIPv4) || len(iface.HardwareAddr) != 6 || iface.MTU <= 0 {
		return nil, fmt.Errorf("device must match the target's Ethernet route (%s)", iface.Name)
	}

	// Get the host MAC from iface
	hostMAC := iface.HardwareAddr

	// Grab host IPv4 address
	hostIPv4 = hostIPv4.To4()
	if hostIPv4 == nil {
		return nil, fmt.Errorf("route has no IPv4 source address")
	}

	// Open pcap handle
	handle, err := pcap.OpenLive(device.Name, 65535, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open failed: %w", err)
	}

	if handle.LinkType() != layers.LinkTypeEthernet {
		handle.Close()
		return nil, fmt.Errorf("capture device is not Ethernet")
	}
	// Set BPF filter so we only catch traffic returning to our port
	bpfFilter := fmt.Sprintf("tcp dst port %d and ip dst %s and tcp src port %d and ip src %s", srcPort, hostIPv4, targetPort, remoteIPBytes)
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to apply BPF filter: %w", err)
	}

	// Set up gVisor user-space TCP stack config
	gvisorIP := tcpip.AddrFrom4([4]byte(hostIPv4))
	mtu := iface.MTU
	linkEP := channel.New(256, uint32(mtu), tcpip.LinkAddress(hostMAC))

	// Create a new TCP/IP stack
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	workerCtx, cancel := context.WithCancel(context.Background())

	// Block the port that we are establishing a connection on so the kernel doesn't interfere
	isolator := isolator.NewIsolator()
	if err := isolator.Isolate(ctx, srcPort); err != nil {
		return nil, fmt.Errorf("failed to setup platform host protection: %w", err)
	}

	owned := &ownedConn{stack: s, link: linkEP, handle: handle, cancel: cancel, isolator: isolator, srcPort: srcPort}
	success := false
	defer func() {
		if !success {
			dialErr = errors.Join(dialErr, owned.Close())
		}
	}()

	// Create a new in-memory NIC
	if err := s.CreateNIC(1, linkEP); err != nil {
		return nil, fmt.Errorf("gvisor NIC creation failed: %v", err)
	}

	// Create new IPv4 address with subnet prefix
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: gvisorIP.WithPrefix(),
	}

	// Add address to the NIC we just created
	if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("gvisor IP config failed: %v", err)
	}

	// Send all traffic through this NIC
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
	})

	// Resolve gateway's MAC address
	if gateway == nil || gateway.IsUnspecified() {
		gateway = remoteIPBytes
	}
	arpCtx, arpCancel := context.WithTimeout(ctx, 5*time.Second)
	defer arpCancel()
	gatewayMAC, err := network.ResolveARP(arpCtx, device, hostMAC, hostIPv4, gateway)
	if err != nil {
		return nil, fmt.Errorf("resolving gateway MAC: %w", err)
	}

	// Start workers for ingress and egress traffic
	owned.workers.Add(2)
	go func() {
		defer owned.workers.Done()
		owned.workerFailed(StartEgressWorker(workerCtx, linkEP, handle, hostMAC, gatewayMAC))
	}()
	go func() { defer owned.workers.Done(); owned.workerFailed(StartIngressWorker(workerCtx, handle, linkEP)) }()

	// Allow workers to initialize
	// Workers can consume packets queued before they are scheduled.

	// Connect via gVisor TCP layer
	remoteIP := tcpip.AddrFrom4([4]byte(remoteIPBytes))

	localAddr := tcpip.FullAddress{Addr: gvisorIP, Port: uint16(srcPort)}
	remoteAddr := tcpip.FullAddress{Addr: remoteIP, Port: uint16(targetPort)}

	conn, err := gonet.DialTCPWithBind(ctx, s, localAddr, remoteAddr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("tcp handshake failed via netstack: %w", err)
	}

	owned.Conn = conn
	success = true
	return owned, nil
}

// Capture device names can differ from net.Interface names (for example, Npcap
// device paths on Windows). Match the route source address when names differ.
func deviceMatchesRoute(device *pcap.Interface, iface *net.Interface, src net.IP) bool {
	if device.Name == iface.Name {
		return true
	}
	for _, address := range device.Addresses {
		if address.IP.Equal(src) {
			return true
		}
	}
	return false
}
