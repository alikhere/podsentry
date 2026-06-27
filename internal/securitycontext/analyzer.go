package securitycontext

import (
	corev1 "k8s.io/api/core/v1"
)

// Report holds all security context findings for a pod.
type Report struct {
	PodName         string
	Namespace       string
	Capabilities    []CapabilityFinding
	Privilege       []PrivilegeFinding
	Seccomp         []SeccompFinding
	HostNamespaces  []HostNamespaceFinding
}

// Analyzer runs security context checks against a PodSpec.
type Analyzer struct{}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze performs all security context checks and returns a Report.
func (a *Analyzer) Analyze(name, namespace string, spec *corev1.PodSpec) Report {
	return Report{
		PodName:        name,
		Namespace:      namespace,
		Capabilities:   AnalyzeCapabilities(spec),
		Privilege:      AnalyzePrivilege(spec),
		Seccomp:        AnalyzeSeccomp(spec),
		HostNamespaces: AnalyzeHostNamespaces(spec),
	}
}

func allContainers(spec *corev1.PodSpec) []corev1.Container {
	containers := make([]corev1.Container, 0, len(spec.Containers)+len(spec.InitContainers))
	containers = append(containers, spec.Containers...)
	containers = append(containers, spec.InitContainers...)
	return containers
}
