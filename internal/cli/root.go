// The root command for the cobra cli
package cli

import (
	"os"

	"github.com/spf13/cobra"
)

// Declare flag variables
var udpTarget string
var port string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "doodlebob",
	Short: "The CLI tool for doodlebob",
	Long: `The CLI tool for doodlebob.
	Allows remote code execution via gopacket/pcap, bypassing host firewalls.
	Currently allows command execution, reverse shells, and heartbeats.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&udpTarget, "target", "t", "", "Specify the UDP destination host")
	rootCmd.PersistentFlags().StringVarP(&port, "port", "p", "53", "Specify a destination port for the UDP packet (not the target of the command)")
}
