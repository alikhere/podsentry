package pss

import corev1 "k8s.io/api/core/v1"

// Severity represents the severity level of a policy violation.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Violation describes a single policy violation found in a Pod spec.
type Violation struct {
	ID          string
	Rule        string
	Severity    Severity
	Message     string
	Container   string
	Remediation string
}

// Rule is the interface implemented by every PSS policy check.
type Rule interface {
	ID() string
	Name() string
	Level() Level
	Check(spec *corev1.PodSpec) []Violation
}
