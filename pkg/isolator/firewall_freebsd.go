// Contains the FreeBSD implementation of the FlowIsolator interface
//go:build freebsd

package isolator

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const (
	// Root anchor matching all user isolation containers
	MainAnchor = "doodlebob-Isolate"
	// Sub-anchor per individual isolated port
	SubAnchorFormat = "doodlebob-Isolate/%d"
)

type FreeBSDIsolator struct {
	initOnce sync.Once
	initErr  error
}

func NewIsolator() FlowIsolator {
	return &FreeBSDIsolator{}
}

func validatePort(srcPort int) error {
	if srcPort < 1 || srcPort > 65535 {
		return fmt.Errorf("invalid source port: %d", srcPort)
	}
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func runPFCTL(ctx context.Context, rules string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "pfctl", args...)
	if rules != "" {
		cmd.Stdin = bytes.NewBufferString(rules)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("pfctl %v failed: %w: %s", args, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

// ensurePFReady guarantees the kernel module is loaded, PF is enabled, and the root anchor is attached
func (f *FreeBSDIsolator) ensurePFReady(ctx context.Context) error {
	f.initOnce.Do(func() {
		// 1. Ensure kernel module is loaded
		if _, err := runCommand(ctx, "kldload", "pf"); err != nil {
			// Ignore error if it's already loaded
			if !strings.Contains(err.Error(), "File exists") && !strings.Contains(err.Error(), "already loaded") {
				f.initErr = fmt.Errorf("failed to load pf kernel module: %w", err)
				return
			}
		}

		// 2. Check if PF is running
		infoOut, err := runPFCTL(ctx, "", "-s", "info")
		if err != nil {
			f.initErr = fmt.Errorf("failed to check pf status: %w", err)
			return
		}

		// 3. Initialize PF with a permissive rule allowing our anchor if disabled
		if strings.Contains(string(infoOut), "Status: Disabled") {
			// Pass-all ruleset containing our structural isolation hook
			baseRules := fmt.Sprintf("anchor %s\npass out all\npass in all\n", MainAnchor)
			if _, err := runPFCTL(ctx, baseRules, "-f", "-"); err != nil {
				f.initErr = fmt.Errorf("failed to load initial ruleset: %w", err)
				return
			}
			if _, err := runPFCTL(ctx, "", "-e"); err != nil {
				f.initErr = fmt.Errorf("failed to enable pf: %w", err)
				return
			}
		} else {
			// 4. If already enabled, append our root anchor dynamically if it doesn't exist
			rulesOut, err := runPFCTL(ctx, "", "-s", "rules")
			if err != nil {
				f.initErr = fmt.Errorf("failed to read existing rules: %w", err)
				return
			}
			if !strings.Contains(string(rulesOut), fmt.Sprintf("anchor %sall", MainAnchor)) {
				anchorRule := fmt.Sprintf("anchor %s\n", MainAnchor)
				// Open parsing and append the root anchor safely to the live ruleset
				if _, err := runPFCTL(ctx, anchorRule, "-g", "-f", "-"); err != nil {
					f.initErr = fmt.Errorf("failed to ensure anchor presence in active configuration: %w", err)
					return
				}
			}
		}
	})

	return f.initErr
}

func (f *FreeBSDIsolator) Isolate(ctx context.Context, srcPort int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePort(srcPort); err != nil {
		return err
	}
	if err := f.ensurePFReady(ctx); err != nil {
		return fmt.Errorf("pf initialization failed: %w", err)
	}

	anchor := fmt.Sprintf(SubAnchorFormat, srcPort)
	port := strconv.Itoa(srcPort)

	// 5. Install the source-port-specific RST-blocking rule inside its explicit nested sub-anchor
	rule := fmt.Sprintf(
		"block drop out quick proto tcp from any port %s to any flags R/R\n",
		port,
	)

	if _, err := runPFCTL(ctx, rule, "-a", anchor, "-f", "-"); err != nil {
		return fmt.Errorf("failed to install PF isolation rule for port %d: %w", srcPort, err)
	}

	return nil
}

func (f *FreeBSDIsolator) Release(ctx context.Context, srcPort int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePort(srcPort); err != nil {
		return err
	}

	anchor := fmt.Sprintf(SubAnchorFormat, srcPort)

	// 6. Remove only the rule scoped to this specific client port sub-anchor
	_, err := runPFCTL(ctx, "", "-a", anchor, "-F", "rules")
	if err != nil {
		// If the anchor context was already empty/gone, treat it as a success
		if strings.Contains(err.Error(), "Anchor not found") {
			return nil
		}
		return fmt.Errorf("failed to release PF isolation rule for port %d: %w", srcPort, err)
	}

	return nil
}
