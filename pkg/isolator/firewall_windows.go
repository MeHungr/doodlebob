// Contains the Windows implementation of the FlowIsolator interface
//go:build windows

package isolator

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

var RULE_FORMAT string = "doodlbob-Isolate-%s"

type WindowsIsolator struct{}

func NewIsolator() FlowIsolator { return &WindowsIsolator{} }

// Isolate blocks traffic out of a source port on the Windows firewall
// This allows the pcap interface to send and receive traffic
// Without the kernel interfering with RST packets
// An outbound rule is generally more stealthy than inbound
func (w *WindowsIsolator) Isolate(ctx context.Context, srcPort int) error {
	portStr := strconv.Itoa(srcPort)
	ruleName := fmt.Sprintf(RULE_FORMAT, portStr)

	// Block outbound RST packets by targeting TCP on the specific local source port
	cmd := exec.CommandContext(
		ctx,
		"netsh",
		"advfirewall",
		"firewall",
		"add",
		"rule",
		"name="+ruleName,
		"dir=out",
		"action=block",
		"protocol=TCP",
		"localport="+portStr,
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add windows firewall rule: %w", err)
	}

	return nil
}

// Release removes the firewall rule set by Isolate
func (w *WindowsIsolator) Release(ctx context.Context, srcPort int) error {
	portStr := strconv.Itoa(srcPort)
	ruleName := fmt.Sprintf(RULE_FORMAT, portStr)

	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add windows firewall rule: %w", err)
	}

	return nil
}
