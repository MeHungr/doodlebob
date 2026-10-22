package cli

import "github.com/spf13/cobra"

var commandCommand = &cobra.Command{
	Use: "command <target-ip> \"<command>\"",
	Short: "Executes a command on the target",
	Long: `Executes a command on the target.
	Defaults to <target-ip>:53 for the UDP target, can be changed with flags
	Example:
		doodlebob command 192.168.10.1 "whoami"`,
		Args: cobra.MinimumNArgs(2), // Ensures at least 2 arguments
		RunE: func(cmd *cobra.Command, args []string) error {
			targetIP := args[0]
			command := args[1]

			// Run the OpenShell function when the command is run
			err := SendCommand(udpTarget, targetIP, port, command)
			if err != nil {
				return err
			}

			return nil
		},
}

func init() {
	rootCmd.AddCommand(commandCommand)

	// Add a flag for udp target and udp port
	commandCommand.Flags().StringVarP(&udpTarget, "target", "t", udpTarget, "Specify a destination host for the UDP packet (not the target of the command)")
	commandCommand.Flags().StringVarP(&port, "port", "p", "53", "Specify a destination port for the UDP packet (not the target of the command)")
}
