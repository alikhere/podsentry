package cmd

import (
	"fmt"
	"os"

	"github.com/alikhere/podsentry/internal/loader"
	"github.com/alikhere/podsentry/internal/pss"
	"github.com/alikhere/podsentry/internal/report"
	"github.com/alikhere/podsentry/internal/securitycontext"
	"github.com/alikhere/podsentry/internal/userns"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <path>",
	Short: "Full combined security inspection",
	Long: `Runs all available checks (PSS, user namespace, security context) against Pod specs
and produces a unified report.

Examples:
  podsentry inspect pod.yaml
  podsentry inspect ./manifests/ --recursive --output json`,
	Args: cobra.ExactArgs(1),
	RunE: runInspect,
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}

func runInspect(cmd *cobra.Command, args []string) error {
	pods, err := loader.Load(args[0], recursive)
	if err != nil {
		return fmt.Errorf("loading pods: %w", err)
	}

	if len(pods) == 0 {
		fmt.Fprintln(os.Stderr, "No Pod documents found")
		return nil
	}

	evaluator, err := pss.NewEvaluator(pss.LevelRestricted)
	if err != nil {
		return fmt.Errorf("creating PSS evaluator: %w", err)
	}

	inspector := userns.NewInspector()
	analyzer := securitycontext.NewAnalyzer()

	var reports []report.InspectReport
	for _, pod := range pods {
		pssResult := evaluator.Evaluate(pod.Name, pod.Namespace, pod.Spec)
		userNSReport := inspector.Inspect(pod.Name, pod.Namespace, pod.Spec)
		secCtxReport := analyzer.Analyze(pod.Name, pod.Namespace, pod.Spec)

		reports = append(reports, report.InspectReport{
			PodName:   pod.Name,
			Namespace: pod.Namespace,
			Source:    pod.Source,
			PSS:       &pssResult,
			UserNS:    &userNSReport,
			SecCtx:    &secCtxReport,
		})
	}

	if report.Format(outputFormat) == report.FormatJSON {
		return report.WriteInspectJSON(os.Stdout, reports)
	}

	for _, r := range reports {
		fmt.Fprintf(os.Stdout, "\n════════════════════════════════════════\n")
		fmt.Fprintf(os.Stdout, " Pod: %s/%s\n", r.Namespace, r.PodName)
		fmt.Fprintf(os.Stdout, " Source: %s\n", r.Source)
		fmt.Fprintf(os.Stdout, "════════════════════════════════════════\n")

		report.WritePSSTable(os.Stdout, []pss.Result{*r.PSS})
		report.WriteUserNSTable(os.Stdout, r.UserNS)
		report.WriteSecCtxTable(os.Stdout, r.SecCtx)
	}

	if exitCode {
		for _, r := range reports {
			if !r.PSS.Pass {
				os.Exit(1)
			}
		}
	}

	return nil
}
