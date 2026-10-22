package cli

import (
	"github.com/MeHungr/doodlebob/internal/network"
	"github.com/spf13/cobra"
)

var responsePort string

var heartbeatCommand = &cobra.Command{
	Use:   "heartbeat <target-ip>",
	Short: "Queries the target for a sign of life (heartbeat)",
	Long: `Asks the target to send back a UDP packet showing it can be reached (heartbeat).
	Defaults to <target-ip>:53 for the UDP target, can be changed with flags
	Example:
		doodlebob heartbeat 192.168.10.1`,
	Args: cobra.MinimumNArgs(1), // Ensures at least 1 argument
	RunE: func(cmd *cobra.Command, args []string) error {
		targetIP := args[0]

		if !cmd.Flags().Changed("target") {
			udpTarget = targetIP
		}

		// Run the OpenShell function when the command is run
		err := Heartbeat(udpTarget, targetIP, port, network.LocalIP().IP.To4().String(), responsePort)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(heartbeatCommand)

	// Add a flag for udp target and udp port
	heartbeatCommand.Flags().StringVarP(&responsePort, "response-port", "r", "8080", "Specify a response port for the UDP packet (not the target of the command)")
}
