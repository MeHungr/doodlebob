# doodlebob

### **Author:** Dylan Weber (dmw7938@rit.edu)

doodlebob is a Command and Control (C2) framework built in Go that utilizes `gopacket` and `pcap` to achieve Remote Code Execution (RCE) on both Windows and Linux platforms.

<img width="500" height="500" alt="DoodleBob Character" src="https://github.com/user-attachments/assets/20ef17e6-5ffc-4df1-adac-ad013d2b3714" />

---

## The Idea

The doodlebob CLI communicates with a packet listener on the target host over UDP using the `gopacket/pcap` packages. 

Because these packets are intercepted via packet capture before they reach the kernel's standard networking stack, they can effectively bypass traditional host-based firewalls. This mimics the core mechanisms used by protocol monitoring utilities such as [Wireshark](https://www.wireshark.org/) and [tcpdump](https://www.tcpdump.org/).

---

## Repository Structure

The project is organized into the following components:

* **`bin/`** – Contains compiled binaries (linux_amd64 is currently Arch-based).
* **`cmd/`** – Main entry points for the application binaries.
* **`deploy/`** – Ansible deployment playbooks and target configurations.
* **`internal/`** – Private application frameworks and operational modules.
  * **`internal/cli/`** – Command-line user interface implemented using the Cobra CLI framework.
* **`pkg/executor`** – Core system packages handling command execution and payload logic.
* **`Makefile`** – Automation scripts for local building, compilation, and setup.
* **`go.mod` / `go.sum`** – Go runtime dependencies and module version definition.

---

## Prerequisites

To compile, build, or deploy this framework, your environments require:

* **Go Development Environment** – Latest stable Golang toolchain installed locally.
* **PCAP Component Libraries** – System-level library architecture mapped to your platform:
  * **Linux:** `libpcap` along with its development packages (e.g., `libpcap-dev` on Debian/Ubuntu systems).
  * **Windows:** [Npcap](https://npcap.com/#download) or legacy `WinPcap` configurations.

---

## Installation & Deployment

### 1. Target Preparation (Windows Only)
Automated playbooks cannot auto-install the required kernel driver on Windows systems. You must manually download and execute the [Npcap Installer](https://npcap.com/#download) on all targeted Windows hosts before initiating Ansible workflows.

### 2. Automated Agent Deployment
Use the integrated Ansible orchestration scripts inside the deployment folder to initialize background persistence services:

```bash
ansible-playbook -i deploy/your_inventory_file deploy/deploy.yml
```
This automated flow handles:
* Setting up Linux dependencies.
* Creating, registering, and enabling the background persistence daemon on both Linux and Windows.

---

## Usage

For control hosts running Debian-based Linux, provision the operational CLI to your local system paths using the included pipeline configuration:

```bash
# Compile and install the Cobra CLI application to your local binary path
make install
```

> [!WARNING]  
> Executing a raw `make` command compiles binaries directly into the workspace root and will overwrite any existing precompiled binaries stored in the `bin/` directory.

### Commands
Use the command `<doodlebob-binary> help` for more information. \
If you have any permission issues, run as root. \
Examples:
* `doodlebob heartbeat 192.168.10.5`
  * If this doesn't work, `doodlebob heartbeat 192.168.10.5 -t 192.168.10.5`,
  * OR use a broadcast address for the `-t` flag, ex: `doodlebob heartbeat 192.168.10.5 -t 192.168.10.255`
  * This applies to all commands, and has to do with the way packets are routed by switches
* `doodlebob shell 192.168.10.5`
* `doodlebob command 192.168.10.5 "touch /home/file.txt"`
  * Note: commands do NOT return any output to remain simple, lightweight, and more stealthy. Use heartbeat to test connectivity.

### Compilation Context
libpcap is hard to cross compile, and I'm recycling my Makefile from another project, so it's slightly finicky for now. If you are operating from a Debian control machine, you can alternately utilize the pre-built application file found inside the `bin/` directory.

---

## Disclaimer

This software is developed primarily for competition and educational use. Unauthorized use of this software against target systems without explicit prior consent is illegal.
