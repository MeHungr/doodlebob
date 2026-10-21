// The main agent entrypoint
// This can be run with no arguments to run in the foreground,
// or, it accepts arguments for running as a service.
// Valid arguments:
//
//	install
//	uninstall
//	start
//	stop
package main

import (
	"log"
	"os"

	"github.com/MeHungr/doodlebob/internal/agent"
	"github.com/kardianos/service"
)

// main starts a listener
func main() {
	// Get the service configuration depending on OS
	config := agent.GetServiceConfig()
	prg := &agent.Program{}

	// Create a new service
	svc, err := service.New(prg, config)
	if err != nil {
		log.Fatalf("service.New: %v", err)
	}

	// Allows control functions
	if len(os.Args) > 1 {
		if err := service.Control(svc, os.Args[1]); err != nil {
			log.Fatalf("Valid actions: install, uninstall, start, stop. Error: %v", err)
		}
		return
	}

	// svc.Run will block and run in foreground if no arguments are provided
	if err := svc.Run(); err != nil {
		log.Fatalf("service run error: %v", err)
	}
}
