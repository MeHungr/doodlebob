// Contains the FreeBSD implementation of the FlowIsolator interface
//go:build freebsd

package isolator

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

const RULE_FORMAT = "doodlebob-Isolate-%d"

type FreeBSDIsolator struct{}

func NewIsolator() FlowIsolator {
	return &FreeBSDIsolator{}
}

func validatePort(srcPort int) error {
	if srcPort < 1 || srcPort > 65535 {
		return fmt.Errorf("invalid source port: %d", srcPort)
	}
	return nil
}

func runPFCTL(
	ctx context.Context,
	rules string,
	args ...string,
) error {
	cmd := exec.CommandContext(ctx, "pfctl", args...)

	if rules != "" {
		cmd.Stdin = bytes.NewBufferString(rules)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"pfctl %v failed: %w: %s",
			args, err, output,
		)
	}

	return nil
}

func (f *FreeBSDIsolator) Isolate(
	ctx context.Context,
	srcPort int,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePort(srcPort); err != nil {
		return err
	}

	anchor := fmt.Sprintf(RULE_FORMAT, srcPort)
	port := strconv.Itoa(srcPort)

	// R/R matches TCP packets with RST set,
	// regardless of the other TCP flags.
	rule := fmt.Sprintf(
		"block drop out quick proto tcp "+
			"from any port %s to any flags R/R\n",
		port,
	)

	if err := ctx.Err(); err != nil {
		return err
	}

	// Replace only this anchor's rules.
	if err := runPFCTL(
		ctx, rule, "-a", anchor, "-f", "-",
	); err != nil {
		return fmt.Errorf(
			"failed to install PF isolation rule: %w", err,
		)
	}

	return nil
}

func (f *FreeBSDIsolator) Release(
	ctx context.Context,
	srcPort int,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePort(srcPort); err != nil {
		return err
	}

	anchor := fmt.Sprintf(RULE_FORMAT, srcPort)

	if err := ctx.Err(); err != nil {
		return err
	}

	// Flush filter rules from this anchor only.
	if err := runPFCTL(
		ctx, "", "-a", anchor, "-F", "rules",
	); err != nil {
		return fmt.Errorf(
			"failed to release PF isolation rule: %w", err,
		)
	}

	return nil
}
