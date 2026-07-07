package cmd

import (
	"fmt"
	"os"

	"github.com/alikhere/podsentry/internal/loader"
	"github.com/alikhere/podsentry/internal/report"
	"github.com/alikhere/podsentry/internal/userns"
	"github.com/spf13/cobra"
)

var usernsCmd = &cobra.Command{
	Use:   "userns <path>",
	Short: "Inspect user namespace configuration",
	Long: `Inspects the hostUsers field and user namespace configuration of Pod specs.
Reports UID mapping implications and conflicts with other security settings.

Examples:
  podsentry userns pod.yaml
  podsentry userns ./manifests/ --recursive`,
	Args: cobra.ExactArgs(1),
	RunE: runUserNS,
}

func init() {
	rootCmd.AddCommand(usernsCmd)
}

func runUserNS(cmd *cobra.Command, args []string) error {
	pods, err := loader.Load(args[0], recursive)
	if err != nil {
		return fmt.Errorf("loading pods: %w", err)
	}

	if len(pods) == 0 {
		fmt.Fprintln(os.Stderr, "No Pod documents found")
		return nil
	}

	inspector := userns.NewInspector()

	for _, pod := range pods {
		r := inspector.Inspect(pod.Name, pod.Namespace, pod.Spec)

		if report.Format(outputFormat) == report.FormatJSON {
			enc := report.NewJSONEncoder(os.Stdout)
			if err := enc.Encode(r); err != nil {
				return err
			}
		} else {
			report.WriteUserNSTable(os.Stdout, &r)
		}
	}

	return nil
}
