BINARY_DIR := ./bin
GO := go

PKG_AGENT := ./cmd/agent
PKG_CLI := ./cmd/cli

HOSTOS := $(shell go env GOOS)
HOSTARCH := $(shell go env GOARCH)

SHELL :=  /bin/bash

# Release ldflags: strip symbol & DWARF, and trim paths
LDFLAGS := -s -w

# Default build type (release)
.PHONY: all
# all: clean linux-x64 linux-arm mac freebsd windows install
 all: clean linux-x64 windows install

# Default install prefix (Linux/macOS)
PREFIX ?= $(HOME)/.local

# -------- Release builds (stripped) --------

# Linux x64 install
.PHONY: linux-x64
linux-x64:
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/linux_amd64/doodleagent $(PKG_AGENT)
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/linux_amd64/doodlebob $(PKG_CLI)

# # Linux ARM install (Requires gcc-aarch64-linux-gnu cross-compiler)
# .PHONY: linux-arm
# linux-arm:
# 	@command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || \
# 		{ echo "Error: arm64 cross-compiler not installed (need aarch64-linux-gnu-gcc)"; exit 1; }
# 	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/linux_arm64/doodleagent $(PKG_AGENT)
# 	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/linux_arm64/doodlebob $(PKG_CLI)
#
# # Mac install
# .PHONY: mac
# mac:
# 	GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/darwin_amd64/doodleagent $(PKG_AGENT)
# 	GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/darwin_amd64/doodlebob $(PKG_CLI)
#
# FreeBSD install
.PHONY: freebsd
freebsd:
	GOOS=freebsd GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/freebsd_amd64/doodleagent $(PKG_AGENT)
	GOOS=freebsd GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/freebsd_amd64/doodlebob $(PKG_CLI)

# Windows install
.PHONY: windows
windows:
ifeq ($(OS),Windows_NT)
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/windows_amd64/doodleagent.exe $(PKG_AGENT)
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/windows_amd64/doodlebob.exe $(PKG_CLI)
else
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || \
		{ echo "Error: mingw-w64 not installed (need x86_64-w64-mingw32-gcc)"; exit 1; }
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/windows_amd64/doodleagent.exe $(PKG_AGENT)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/windows_amd64/doodlebob.exe $(PKG_CLI)
endif

# -------- Install CLI on Linux/macOS --------
.PHONY: install
install:
	@echo "Installing doodlebob to $(PREFIX)/bin..."
	install -d $(PREFIX)/bin
	install $(BINARY_DIR)/$(HOSTOS)_$(HOSTARCH)/doodlebob $(PREFIX)/bin/doodlebob

	@echo "Installing shell tab completions..."
	# Bash
	install -d $(PREFIX)/share/bash-completion/completions
	$(BINARY_DIR)/$(HOSTOS)_$(HOSTARCH)/doodlebob completion bash > $(PREFIX)/share/bash-completion/completions/doodlebob
	# Zsh
	install -d $(PREFIX)/share/zsh/site-functions
	$(BINARY_DIR)/$(HOSTOS)_$(HOSTARCH)/doodlebob completion zsh > $(PREFIX)/share/zsh/site-functions/_doodlebob
	# Fish
	install -d $(PREFIX)/share/fish/vendor_completions.d
	$(BINARY_DIR)/$(HOSTOS)_$(HOSTARCH)/doodlebob completion fish > $(PREFIX)/share/fish/vendor_completions.d/doodlebob.fish

	@echo "doodlebob installed successfully. Restart your shell or source the completion file."

# -------- Clean --------
.PHONY: clean
clean:
	-rm -rf $(BINARY_DIR)
	-mkdir -p $(BINARY_DIR)

