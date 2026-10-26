// Contains the FreeBSD implementation of the FlowIsolator interface
//go:build freebsd

package isolator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	MainAnchor      = "doodlebob-Isolate"
	SubAnchorFormat = "doodlebob-Isolate/%d"

	pfConfigPath = "/etc/pf.conf"
)

var (
	pfConfigMu sync.Mutex

	anchorDeclaration = `anchor "` + MainAnchor + `"`
	anchorPattern     = regexp.MustCompile(
		`(?m)^\s*anchor\s+"?doodlebob-Isolate"?\s*(?:#.*)?$`,
	)
)

type FreeBSDIsolator struct {
	mu sync.Mutex
}

func NewIsolator() FlowIsolator {
	return &FreeBSDIsolator{}
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid source port: %d", port)
	}
	return nil
}

func runCommand(
	ctx context.Context,
	name string,
	stdin string,
	args ...string,
) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf(
			"%s %v failed: %w: %s",
			name,
			args,
			err,
			strings.TrimSpace(string(output)),
		)
	}

	return output, nil
}

func runPFCTL(
	ctx context.Context,
	stdin string,
	args ...string,
) ([]byte, error) {
	return runCommand(ctx, "pfctl", stdin, args...)
}

// ensurePFModule makes sure /dev/pf is available.
func ensurePFModule(ctx context.Context) error {
	if _, err := os.Stat("/dev/pf"); err == nil {
		return nil
	}

	_, loadErr := runCommand(ctx, "kldload", "", "pf")

	// Check the actual device rather than relying on kldload's
	// error message. PF may already be compiled into the kernel.
	if _, err := os.Stat("/dev/pf"); err != nil {
		return fmt.Errorf(
			"PF device unavailable after kldload: %w (load error: %v)",
			err,
			loadErr,
		)
	}

	return nil
}

// insertAnchor inserts the anchor before existing filtering rules.
//
// PF configuration sections have a defined ordering. Inserting
// an anchor after pass/block rules can cause parsing failures.
//
// This handles ordinary pf.conf configurations; configurations
// using complex macros, includes, or generated rules may need
// a dedicated configuration manager.
func insertAnchor(config string) string {
	if anchorPattern.MatchString(config) {
		return config
	}

	lines := strings.Split(config, "\n")

	// Place the anchor after translation rules but before the
	// first ordinary filtering rule.
	insertAt := len(lines)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "block ") ||
			strings.HasPrefix(trimmed, "pass ") ||
			strings.HasPrefix(trimmed, "match ") ||
			strings.HasPrefix(trimmed, "anchor ") {
			insertAt = i
			break
		}
	}

	lines = append(lines, "")
	copy(lines[insertAt+1:], lines[insertAt:])
	lines[insertAt] = anchorDeclaration

	return strings.Join(lines, "\n")
}

// installRootAnchor attaches our anchor to the root ruleset.
//
// The original configuration is backed up before modification.
// A temporary configuration is validated before being installed.
func installRootAnchor(ctx context.Context) error {
	pfConfigMu.Lock()
	defer pfConfigMu.Unlock()

	original, err := os.ReadFile(pfConfigPath)

	existed := err == nil

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read PF configuration: %w", err)
	}

	config := string(original)

	if anchorPattern.MatchString(config) {
		// The file contains our declaration, but the running
		// ruleset might not. Reload the configuration below.
	} else {
		config = insertAnchor(config)
	}

	// Use a temporary file in the same directory so rename
	// stays on the same filesystem.
	tmp, err := os.CreateTemp(
		filepath.Dir(pfConfigPath),
		".doodlebob-pf-*.conf",
	)
	if err != nil {
		return fmt.Errorf("create temporary PF config: %w", err)
	}

	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}

	if _, err := tmp.WriteString(config); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	// Validate before touching the active configuration.
	if _, err := runPFCTL(ctx, "", "-nf", tmpPath); err != nil {
		return fmt.Errorf("generated PF configuration invalid: %w", err)
	}

	// Save the original configuration if one exists.
	if existed && config != string(original) {
		backup := fmt.Sprintf(
			"%s.doodlebob.%d.bak",
			pfConfigPath,
			time.Now().UnixNano(),
		)

		if err := os.WriteFile(backup, original, 0600); err != nil {
			return fmt.Errorf("backup PF configuration: %w", err)
		}
	}

	// Install the new configuration on disk.
	if !existed || config != string(original) {
		if err := os.Rename(tmpPath, pfConfigPath); err != nil {
			return fmt.Errorf("install PF configuration: %w", err)
		}
	}

	// Activate the root ruleset.
	if _, err := runPFCTL(ctx, "", "-f", pfConfigPath); err != nil {
		return fmt.Errorf("activate PF configuration: %w", err)
	}

	return nil
}

// rootAnchorAttached checks the active root filter rules.
func rootAnchorAttached(ctx context.Context) (bool, error) {
	output, err := runPFCTL(ctx, "", "-sr")
	if err != nil {
		return false, err
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, anchorDeclaration) ||
			strings.HasPrefix(line, "anchor "+MainAnchor+" ") {
			return true, nil
		}
	}

	return false, nil
}

// ensurePFReady initializes the PF subsystem and attaches
// the application's root anchor when necessary.
func (f *FreeBSDIsolator) ensurePFReady(ctx context.Context) error {
	if err := ensurePFModule(ctx); err != nil {
		return err
	}

	info, err := runPFCTL(ctx, "", "-s", "info")
	if err != nil {
		return fmt.Errorf("check PF status: %w", err)
	}

	attached, err := rootAnchorAttached(ctx)
	if err != nil {
		return fmt.Errorf("check root anchor: %w", err)
	}

	if !attached {
		if err := installRootAnchor(ctx); err != nil {
			return err
		}
	}

	// Attach the wildcard dispatcher in the parent anchor.
	//
	// Individual subanchors:
	// doodlebob-Isolate/12345
	// doodlebob-Isolate/2500
	//
	// are evaluated through this rule.
	dispatch := fmt.Sprintf(
		"anchor \"%s/*\"\n",
		MainAnchor,
	)

	if _, err := runPFCTL(
		ctx,
		dispatch,
		"-a", MainAnchor,
		"-f", "-",
	); err != nil {
		return fmt.Errorf("install PF anchor dispatcher: %w", err)
	}

	if strings.Contains(string(info), "Status: Disabled") {
		if _, err := runPFCTL(ctx, "", "-e"); err != nil {
			return fmt.Errorf("enable PF: %w", err)
		}
	}

	return nil
}

// Isolate blocks outbound TCP RST packets originating from srcPort.
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

	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.ensurePFReady(ctx); err != nil {
		return fmt.Errorf("initialize PF: %w", err)
	}

	anchor := fmt.Sprintf(SubAnchorFormat, srcPort)

	rule := fmt.Sprintf(
		"block drop out quick proto tcp "+
			"from any port %d to any flags R/R\n",
		srcPort,
	)

	if _, err := runPFCTL(
		ctx,
		rule,
		"-a", anchor,
		"-f", "-",
	); err != nil {
		return fmt.Errorf(
			"install RST isolation rule for port %d: %w",
			srcPort,
			err,
		)
	}

	return nil
}

// Release removes the RST isolation rule for srcPort.
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

	f.mu.Lock()
	defer f.mu.Unlock()

	anchor := fmt.Sprintf(SubAnchorFormat, srcPort)

	if _, err := runPFCTL(
		ctx,
		"",
		"-a", anchor,
		"-F", "rules",
	); err != nil {
		return fmt.Errorf(
			"release RST isolation rule for port %d: %w",
			srcPort,
			err,
		)
	}

	return nil
}
