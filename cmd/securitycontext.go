package cmd

import (
	"fmt"
	"os"

	"github.com/alikhere/podsentry/internal/loader"
	"github.com/alikhere/podsentry/internal/report"
	"github.com/alikhere/podsentry/internal/securitycontext"
	"github.com/spf13/cobra"
)

var secCtxCmd = &cobra.Command{
	Use:   "securitycontext <path>",
	Short: "Audit security context settings",
	Long: `Analyzes security context settings for all containers in Pod specs.
Checks capabilities, privilege escalation, seccomp profiles, and host namespace usage.

Examples:
  podsentry securitycontext pod.yaml
  podsentry securitycontext ./manifests/ --recursive`,
	Args: cobra.ExactArgs(1),
	RunE: runSecurityContext,
}

func init() {
	rootCmd.AddCommand(secCtxCmd)
}

func runSecurityContext(cmd *cobra.Command, args []string) error {
	pods, err := loader.Load(args[0], recursive)
	if err != nil {
		return fmt.Errorf("loading pods: %w", err)
	}

	if len(pods) == 0 {
		fmt.Fprintln(os.Stderr, "No Pod documents found")
		return nil
	}

	analyzer := securitycontext.NewAnalyzer()

	for _, pod := range pods {
		r := analyzer.Analyze(pod.Name, pod.Namespace, pod.Spec)

		if report.Format(outputFormat) == report.FormatJSON {
			enc := report.NewJSONEncoder(os.Stdout)
			if err := enc.Encode(r); err != nil {
				return err
			}
		} else {
			report.WriteSecCtxTable(os.Stdout, &r)
		}
	}

	return nil
}
