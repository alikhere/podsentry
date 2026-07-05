package cmd

import (
	"fmt"
	"os"

	"github.com/alikhere/podsentry/internal/loader"
	"github.com/alikhere/podsentry/internal/pss"
	"github.com/alikhere/podsentry/internal/report"
	"github.com/spf13/cobra"
)

var pssLevel string

var pssCmd = &cobra.Command{
	Use:   "pss <path>",
	Short: "Check Pod specs against Pod Security Standards",
	Long: `Evaluates Pod YAML specs against the Kubernetes Pod Security Standards.
Supports all three levels: privileged, baseline, and restricted.

Examples:
  podsentry pss pod.yaml
  podsentry pss pod.yaml --level restricted
  podsentry pss ./manifests/ --recursive --exit-code`,
	Args: cobra.ExactArgs(1),
	RunE: runPSS,
}

func init() {
	pssCmd.Flags().StringVar(&pssLevel, "level", "baseline", "PSS level: privileged, baseline, or restricted")
	rootCmd.AddCommand(pssCmd)
}

func runPSS(cmd *cobra.Command, args []string) error {
	level, ok := pss.ParseLevel(pssLevel)
	if !ok {
		return fmt.Errorf("unknown PSS level %q; must be one of: privileged, baseline, restricted", pssLevel)
	}

	evaluator, err := pss.NewEvaluator(level)
	if err != nil {
		return fmt.Errorf("creating evaluator: %w", err)
	}

	pods, err := loader.Load(args[0], recursive)
	if err != nil {
		return fmt.Errorf("loading pods: %w", err)
	}

	if len(pods) == 0 {
		fmt.Fprintln(os.Stderr, "No Pod documents found")
		return nil
	}

	var results []pss.Result
	for _, pod := range pods {
		result := evaluator.Evaluate(pod.Name, pod.Namespace, pod.Spec)
		results = append(results, result)
	}

	switch report.Format(outputFormat) {
	case report.FormatJSON:
		if err := report.WritePSSJSON(os.Stdout, results); err != nil {
			return err
		}
	default:
		report.WritePSSTable(os.Stdout, results)
		summary := report.Summarize(results)
		report.WriteSummary(os.Stdout, summary)
	}

	if exitCode {
		for _, r := range results {
			if !r.Pass {
				os.Exit(1)
			}
		}
	}

	return nil
}
