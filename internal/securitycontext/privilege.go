package securitycontext

import (
	corev1 "k8s.io/api/core/v1"
)

// PrivilegeFinding describes a privilege-related finding for a container.
type PrivilegeFinding struct {
	Container              string
	Privileged             bool
	AllowPrivilegeEscalation *bool
	RunAsNonRoot           *bool
	RunAsUser              *int64
	RunAsGroup             *int64
	Severity               string
	Issues                 []string
}

// AnalyzePrivilege inspects privilege-related settings for all containers.
func AnalyzePrivilege(spec *corev1.PodSpec) []PrivilegeFinding {
	var findings []PrivilegeFinding

	for _, c := range allContainers(spec) {
		f := analyzeContainerPrivilege(c, spec.SecurityContext)
		findings = append(findings, f)
	}

	return findings
}

func analyzeContainerPrivilege(c corev1.Container, podSC *corev1.PodSecurityContext) PrivilegeFinding {
	f := PrivilegeFinding{
		Container: c.Name,
	}

	if c.SecurityContext != nil {
		if c.SecurityContext.Privileged != nil {
			f.Privileged = *c.SecurityContext.Privileged
		}
		f.AllowPrivilegeEscalation = c.SecurityContext.AllowPrivilegeEscalation
		f.RunAsNonRoot = c.SecurityContext.RunAsNonRoot
		f.RunAsUser = c.SecurityContext.RunAsUser
		f.RunAsGroup = c.SecurityContext.RunAsGroup
	}

	if f.Privileged {
		f.Issues = append(f.Issues, "privileged mode is enabled")
	}

	if f.AllowPrivilegeEscalation == nil {
		f.Issues = append(f.Issues, "allowPrivilegeEscalation is not set (defaults to true)")
	} else if *f.AllowPrivilegeEscalation {
		f.Issues = append(f.Issues, "allowPrivilegeEscalation is explicitly true")
	}

	effectiveRunAsNonRoot := (f.RunAsNonRoot != nil && *f.RunAsNonRoot) ||
		(podSC != nil && podSC.RunAsNonRoot != nil && *podSC.RunAsNonRoot)

	if !effectiveRunAsNonRoot {
		if f.RunAsUser == nil {
			if podSC == nil || podSC.RunAsUser == nil {
				f.Issues = append(f.Issues, "runAsNonRoot is not set and runAsUser is not specified")
			} else if *podSC.RunAsUser == 0 {
				f.Issues = append(f.Issues, "pod runAsUser is 0 (root)")
			}
		} else if *f.RunAsUser == 0 {
			f.Issues = append(f.Issues, "runAsUser is 0 (root)")
		}
	}

	switch {
	case len(f.Issues) == 0:
		f.Severity = "pass"
	case f.Privileged:
		f.Severity = "error"
	default:
		f.Severity = "warning"
	}

	return f
}
