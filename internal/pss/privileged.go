package pss

import corev1 "k8s.io/api/core/v1"

// privilegedRules returns rules for the Privileged PSS level, which imposes
// no restrictions — every pod passes.
func privilegedRules() []Rule {
	return []Rule{}
}

// privilegedCheck always returns no violations.
func privilegedCheck(_ *corev1.PodSpec) []Violation {
	return nil
}
