# doodlebob
## Author: Dylan Weber (dmw7938@rit.edu)
doodlebob is a Command and Control (C2) framework built in Go that utilizes `gopacket` and `pcap` to achieve Remote Code Execution (RCE) on both Windows and Linux platforms. \
<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/20ef17e6-5ffc-4df1-adac-ad013d2b3714" />

## The Idea
The doodlebob CLI communicates with a packet listener on the target host over UDP using the `gopacket/pcap` packages. \
This bypasses host-based firewalls, since these packets are intercepted before they are passed to the kernel's networking stack. \
This is how tools like [Wireshark](https://www.wireshark.org/) and [tcpdump](https://www.tcpdump.org/) work.

## Repository Structure

The project is organized into the following directories and files:

* **`bin/`** – Contains compiled binaries.
* **`cmd/`** – Main entry points for the application.
* **`deploy/`** – Deployment configurations and scripts.
* **`internal/`** – Private application and library code.
* **`pkg/executor`** – Core packages handling execution logic.
* **`Makefile`** – Automation scripts for building and managing the project.
* **`go.mod` / `go.sum`** – Go module dependency tracking.

## Prerequisites

To interact with or build this project, ensure you have the following installed:
* **Go** (Golang development environment)
* **pcap library dependencies** (required by `gopacket`, such as `libpcap` on Linux or `WinPcap`/`Npcap` on Windows)
    * To compile the binaries, you will need the libpcap development package

## Installation
**Before deploying with ansible:** \
Unfortunately, [Npcap](https://npcap.com/#download) on Windows must be installed manually, so do that first.

* Run `deploy/deploy.yml` using `ansible-playbook` with an inventory file similar to the example included in the `deploy` directory
* This will install dependencies on Linux, and will install and enable the service on both Linux and Windows provided Npcap is installed on Windows.

## Usage
On the control host, you can run `make` or `make install` from the project root to install the cli to your local bin directory on Linux. \
**Note that if you run `make`, it will overwrite the compiled binaries** \
Alternatively, check the `bin` directory for a precompiled binary that works on Debian \
libpcap is hard to cross compile, and I'm recycling my Makefile from another project, so it's slightly finicky for now.

## Disclaimer

This software is developed primarily for competition and educational use. Unauthorized use of this software against target systems without explicit prior consent is illegal.
