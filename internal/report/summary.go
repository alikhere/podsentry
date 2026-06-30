package report

import (
	"fmt"
	"io"

	"github.com/alikhere/podsentry/internal/pss"
)

// Summary holds aggregated statistics across multiple PSS results.
type Summary struct {
	Total      int
	Passed     int
	Failed     int
	Violations int
}

// Summarize computes a Summary from a slice of PSS results.
func Summarize(results []pss.Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		if r.Pass {
			s.Passed++
		} else {
			s.Failed++
		}
		s.Violations += len(r.Violations)
	}
	return s
}

// WriteSummary prints a human-readable summary line to w.
func WriteSummary(w io.Writer, s Summary) {
	fmt.Fprintf(w, "\nSummary: %d pods checked, %s passed, %s failed, %d violations\n",
		s.Total,
		colorPass.Sprint(fmt.Sprintf("%d", s.Passed)),
		colorError.Sprint(fmt.Sprintf("%d", s.Failed)),
		s.Violations,
	)
}
