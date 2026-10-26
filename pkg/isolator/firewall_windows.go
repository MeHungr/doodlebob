// Contains the Windows implementation of the FlowIsolator interface
//go:build windows

package isolator

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

var RULE_FORMAT string = "doodlebob-Isolate-%d"

type WindowsIsolator struct{}

func NewIsolator() FlowIsolator { return &WindowsIsolator{} }

// isAllFirewallProfilesEnabled ensures all 3 profiles (Domain, Private, Public) are active
func (w *WindowsIsolator) isAllFirewallProfilesEnabled(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "show", "allprofiles", "state")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("failed to check firewall state: %w", err)
	}

	// Count how many profiles are explicitly set to "State ON"
	output := strings.ToUpper(out.String())
	onCount := strings.Count(output, "STATE ON")

	// The firewall has exactly 3 profiles (Domain, Private, Public).
	// If the count is 3, all profiles are enabled.
	if onCount == 3 {
		return true, nil
	}

	return false, nil
}

// enableFirewall turns on all firewall profiles (Domain, Private, and Public)
func (w *WindowsIsolator) enableFirewall(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "set", "allprofiles", "state", "on")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable windows firewall: %w", err)
	}
	return nil
}

// Isolate blocks traffic out of a source port on the Windows firewall
// This allows the pcap interface to send and receive traffic
// Without the kernel interfering with RST packets
// An outbound rule is generally more stealthy than inbound
func (w *WindowsIsolator) Isolate(ctx context.Context, srcPort int) error {
	// Check if ALL profiles are enabled first
	allEnabled, err := w.isAllFirewallProfilesEnabled(ctx)
	if err != nil {
		return err
	}

	// Automatically enable all profiles if even one of them is turned off
	if !allEnabled {
		if err := w.enableFirewall(ctx); err != nil {
			return err
		}
	}

	portStr := strconv.Itoa(srcPort)
	ruleName := fmt.Sprintf(RULE_FORMAT, srcPort)

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
	ruleName := fmt.Sprintf(RULE_FORMAT, srcPort)

	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add windows firewall rule: %w", err)
	}

	return nil
}
