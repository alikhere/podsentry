package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	outputFormat string
	recursive    bool
	exitCode     bool
)

var rootCmd = &cobra.Command{
	Use:   "podsentry",
	Short: "Kubernetes Pod security auditing tool",
	Long: `podsentry audits Kubernetes Pod specs against Pod Security Standards,
inspects user namespace configuration, and reports security context
findings — entirely offline, no cluster required.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	rootCmd.PersistentFlags().BoolVarP(&recursive, "recursive", "r", false, "Recursively scan directories")
	rootCmd.PersistentFlags().BoolVar(&exitCode, "exit-code", false, "Exit with code 1 if any violations are found")
}
