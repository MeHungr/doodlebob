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

const RULE_FORMAT = "doodlebob-Isolate-%d"

type LinuxIsolator struct{}

func NewIsolator() FlowIsolator { return &LinuxIsolator{} }

// Isolate blocks outgoing TCP RST packets originating from srcPort.
// This prevents the kernel from interfering with TCP traffic
// managed through a raw packet interface.
func (l *LinuxIsolator) Isolate(ctx context.Context, srcPort int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if srcPort < 1 || srcPort > 65535 {
		return fmt.Errorf("invalid source port: %d", srcPort)
	}

	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}
	defer nft.CloseLasting()

	// Create a dedicated dual-stack table.
	tableName := fmt.Sprintf(RULE_FORMAT, srcPort)

	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})

	// Hook into locally generated outbound traffic.
	chain := nft.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	expressions := []expr.Any{
		// Match TCP for IPv4 and IPv6.
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		},

		// Match TCP source port.
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(uint16(srcPort)),
		},

		// Read the TCP flags byte.
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13,
			Len:          1,
		},

		// Mask all flags except RST (0x04).
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x04},
			Xor:            []byte{0x00},
		},

		// Match packets with RST set.
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{0x04},
		},

		// Drop matching packets.
		&expr.Verdict{
			Kind: expr.VerdictDrop,
		},
	}

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: expressions,
	})

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("failed to install nftables isolation rule: %w", err)
	}

	return nil
}

// Release removes the isolation table and its associated rules.
func (l *LinuxIsolator) Release(ctx context.Context, srcPort int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if srcPort < 1 || srcPort > 65535 {
		return fmt.Errorf("invalid source port: %d", srcPort)
	}

	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}
	defer nft.CloseLasting()

	tableName := fmt.Sprintf(RULE_FORMAT, srcPort)

	nft.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := nft.Flush(); err != nil {
		return fmt.Errorf("failed to remove nftables isolation table: %w", err)
	}

	return nil
}
