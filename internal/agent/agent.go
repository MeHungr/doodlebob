// Contains the logic for starting an agent
package agent

import "log"

// Start starts the agent
func start() {
	handle, err := ListenDefaultInterface()
	if err != nil {
		log.Fatal(err)
	}

	// Read all incoming packets & print length
	if err := ReadPackets(handle); err != nil {
		log.Fatal(err)
	}

}
