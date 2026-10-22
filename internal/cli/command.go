package cli

import "github.com/spf13/cobra"

var commandCommand = &cobra.Command{
	Use:   "command <target-ip> \"<command>\"",
	Short: "Executes a command on the target",
	Long: `Executes a command on the target.
	Defaults to <target-ip>:6767 for the UDP target, can be changed with flags
	Example:
		doodlebob command 192.168.10.1 "whoami"`,
	Args: cobra.MinimumNArgs(2), // Ensures at least 2 arguments
	RunE: func(cmd *cobra.Command, args []string) error {
		targetIP := args[0]
		command := args[1]

		if !cmd.Flags().Changed("target") {
			udpTarget = targetIP
		}

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
}
