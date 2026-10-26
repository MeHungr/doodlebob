// Defines the isolator struct for creating firewall rules
// This allows a connection on the pcap interface without the host sending RST
package isolator

import (
	"context"
)

type FlowIsolator interface {
	Isolate(ctx context.Context, srcPort int) error
	Release(ctx context.Context, srcPort int) error
}
