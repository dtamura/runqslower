/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "runqslower",
	Short: "Trace high run queue latency",
	Long:  `Trace high run queue latency.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetPid, _ := cmd.Flags().GetUint32("pid")
		minUs := uint64(10000)
		if len(args) > 0 {
			minUs, _ = strconv.ParseUint(args[0], 10, 64)
		}
		runqslower(minUs, targetPid)
	},
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
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.runqslower.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().Uint32P("pid", "p", 0, "trace this PID only")

}
