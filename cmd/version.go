package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version = "2.2.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of DOMEye",
	Long:  `Print the version number and build information of DOMEye.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("DOMEye v%s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
