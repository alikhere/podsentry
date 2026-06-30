package report

import (
	"bytes"
	"testing"

	"github.com/alikhere/podsentry/internal/pss"
)

func TestSummarize(t *testing.T) {
	results := []pss.Result{
		{Pass: true},
		{Pass: false, Violations: []pss.Violation{{}, {}}},
		{Pass: false, Violations: []pss.Violation{{}}},
	}
	s := Summarize(results)
	if s.Total != 3 {
		t.Errorf("expected Total 3, got %d", s.Total)
	}
	if s.Passed != 1 {
		t.Errorf("expected Passed 1, got %d", s.Passed)
	}
	if s.Failed != 2 {
		t.Errorf("expected Failed 2, got %d", s.Failed)
	}
	if s.Violations != 3 {
		t.Errorf("expected Violations 3, got %d", s.Violations)
	}
}

func TestWriteSummary(t *testing.T) {
	var buf bytes.Buffer
	s := Summary{Total: 5, Passed: 3, Failed: 2, Violations: 4}
	WriteSummary(&buf, s)
	if buf.Len() == 0 {
		t.Error("expected non-empty summary output")
	}
}

func TestWritePSSJSON(t *testing.T) {
	results := []pss.Result{
		{
			Name:      "pod",
			Namespace: "default",
			Level:     pss.LevelBaseline,
			Pass:      true,
		},
	}
	var buf bytes.Buffer
	if err := WritePSSJSON(&buf, results); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty JSON output")
	}
}
