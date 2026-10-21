// The main entrypoint for the listener agent
package main

import (
	"log"

	"github.com/MeHungr/doodlebob/internal/agent"
)

// main starts a listener
func main() {
	// Select an interface
	device, err := agent.ChooseInterface()
	if err != nil {
		log.Fatal(err)
	}

	// Begin listening
	if err := agent.Listen(device); err != nil {
		log.Fatal(err)
	}
}
