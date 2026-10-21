// The main entrypoint for the listener agent
package main

import (
	"log"

	"github.com/MeHungr/doodlebob/internal/agent"
)

// main starts a listener
// Can either be run with manual interface selection, or attempt to find the default
func main() {
	// // Select an interface
	// device, err := agent.ChooseInterface()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// // Begin listening
	// handle, err := agent.Listen(device)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	handle, err := agent.ListenDefaultInterface()
	if err != nil {
		log.Fatal(err)
	}

	// Read all incoming packets & print length
	if err := agent.ReadPackets(handle); err != nil {
		log.Fatal(err)
	}
}
