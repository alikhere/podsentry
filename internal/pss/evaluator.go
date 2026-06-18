package pss

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// Result holds the PSS evaluation outcome for a single Pod.
type Result struct {
	Name       string
	Namespace  string
	Level      Level
	Violations []Violation
	Pass       bool
}

// Evaluator runs Pod Security Standard checks against a PodSpec.
type Evaluator struct {
	level Level
	rules []Rule
}

// NewEvaluator creates an Evaluator configured for the given PSS level.
func NewEvaluator(level Level) (*Evaluator, error) {
	var rules []Rule
	switch level {
	case LevelPrivileged:
		rules = privilegedRules()
	case LevelBaseline:
		rules = baselineRules()
	case LevelRestricted:
		rules = restrictedRules()
	default:
		return nil, fmt.Errorf("unknown PSS level: %s", level)
	}
	return &Evaluator{level: level, rules: rules}, nil
}

// Evaluate runs all rules against the given PodSpec and returns the result.
func (e *Evaluator) Evaluate(name, namespace string, spec *corev1.PodSpec) Result {
	var all []Violation
	for _, rule := range e.rules {
		all = append(all, rule.Check(spec)...)
	}
	return Result{
		Name:       name,
		Namespace:  namespace,
		Level:      e.level,
		Violations: all,
		Pass:       len(all) == 0,
	}
}
