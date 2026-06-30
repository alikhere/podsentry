package report

import (
	"github.com/alikhere/podsentry/internal/pss"
	"github.com/alikhere/podsentry/internal/securitycontext"
	"github.com/alikhere/podsentry/internal/userns"
)

// InspectReport is the combined output of all checks for a single pod.
type InspectReport struct {
	PodName   string
	Namespace string
	Source    string
	PSS       *pss.Result
	UserNS    *userns.Report
	SecCtx    *securitycontext.Report
}

// Format controls the output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
)
