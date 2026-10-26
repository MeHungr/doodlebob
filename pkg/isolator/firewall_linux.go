// Contains the Linux implementation of the FlowIsolator interface
//go:build linux

package isolator

import (
	"context"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var RULE_FORMAT string = "doodlbob-Isolate-%s"

type LinuxIsolator struct{}

func NewIsolator() FlowIsolator { return &LinuxIsolator{} }

// func (l *LinuxIsolator) Isolate(ctx context.Context, srcPort int) error {
// 	portStr := strconv.Itoa(srcPort)
// 	cmd := exec.CommandContext(ctx, "iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", portStr, "--tcp-flags", "RST", "RST", "-j", "DROP")
// 	if err := cmd.Run(); err != nil {
// 		return fmt.Errorf("failed to append iptables rule: %w", err)
// 	}
// 	return nil
// }

// Isolate blocks traffic with the RST flag out of a source port on the firewall
// This allows the pcap interface to send and receive traffic
// Without the kernel interfering with RST packets
// An outbound rule is generally more stealthy than inbound
func (l *LinuxIsolator) Isolate(ctx context.Context, srcPort int) error {
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}
	defer nft.CloseLasting()

	// 1. Create a dedicated table to isolate our rules safely
	tableName := fmt.Sprintf(RULE_FORMAT, srcPort)
	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet, // Dual-stack IPv4/IPv6 support
		Name:   tableName,
	})

	// 2. Add an Output chain hooked into the host egress path
	chain := nft.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	// Construct rule expressions to find matching TCP RST packets
	var expressions []expr.Any

	// [ Payload: match TCP protocol ]
	// ip protocol tcp (matches transport protocol in the IP header)
	expressions = append(expressions, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       9, // Protocol field in IPv4 header
		Len:          1,
	})
	expressions = append(expressions, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{unix.IPPROTO_TCP},
	})

	// [ Payload: match local source port ]
	// tcp sport <srcPort>
	expressions = append(expressions, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       0, // Source Port field in TCP header
		Len:          2,
	})
	expressions = append(expressions, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(uint16(srcPort)),
	})

	// [ Payload: match TCP RST flag ]
	// tcp flags & rst == rst
	expressions = append(expressions, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       13, // Flags field in TCP header
		Len:          1,
	})
	expressions = append(expressions, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            1,
		Mask:           []byte{0x04}, // RST flag bit mask
		Xor:            []byte{0x00},
	})
	expressions = append(expressions, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{0x04}, // Must equal 0x04 (RST set)
	})

	// [ Action: Drop the packet ]
	expressions = append(expressions, &expr.Verdict{
		Kind: expr.VerdictDrop,
	})

	// Inject the rule and atomic flush into the kernel
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: expressions,
	})

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables isolation rule: %w", err)
	}

	return nil
}

// Release removes the firewall rule set by Isolate
func (l *LinuxIsolator) Release(ctx context.Context, srcPort int) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}
	defer c.CloseLasting()

	// Deleting the table entirely handles tearing down the chains and inner expressions atomically
	tableName := fmt.Sprintf(RULE_FORMAT, srcPort)
	c.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})

	// Flush the removal transaction to the kernel state table
	if err := c.Flush(); err != nil {
		return fmt.Errorf("failed to tear down nftables isolation table: %w", err)
	}

	return nil
}

// func (l *LinuxIsolator) Release(ctx context.Context, srcPort int) error {
// 	portStr := strconv.Itoa(srcPort)
// 	cmd := exec.CommandContext(ctx, "iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", portStr, "--tcp-flags", "RST", "RST", "-j", "DROP")
// 	return cmd.Run()
// }
