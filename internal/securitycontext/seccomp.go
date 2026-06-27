package securitycontext

import (
	corev1 "k8s.io/api/core/v1"
)

// SeccompFinding describes the seccomp profile configuration for a container.
type SeccompFinding struct {
	Container   string
	ProfileType string
	Source      string
	Severity    string
	Description string
	Remediation string
}

// AnalyzeSeccomp inspects seccomp profile settings at pod and container level.
func AnalyzeSeccomp(spec *corev1.PodSpec) []SeccompFinding {
	var findings []SeccompFinding

	for _, c := range allContainers(spec) {
		f := analyzeContainerSeccomp(c, spec.SecurityContext)
		findings = append(findings, f)
	}

	return findings
}

func analyzeContainerSeccomp(c corev1.Container, podSC *corev1.PodSecurityContext) SeccompFinding {
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
		return profileFinding(c.Name, c.SecurityContext.SeccompProfile, "container")
	}

	if podSC != nil && podSC.SeccompProfile != nil {
		f := profileFinding(c.Name, podSC.SeccompProfile, "pod")
		return f
	}

	return SeccompFinding{
		Container:   c.Name,
		ProfileType: "unconfined",
		Source:      "none",
		Severity:    "error",
		Description: "No seccomp profile is configured. Container runs with unrestricted syscalls.",
		Remediation: "Set securityContext.seccompProfile.type: RuntimeDefault at pod or container level",
	}
}

func profileFinding(container string, profile *corev1.SeccompProfile, source string) SeccompFinding {
	switch profile.Type {
	case corev1.SeccompProfileTypeRuntimeDefault:
		return SeccompFinding{
			Container:   container,
			ProfileType: "RuntimeDefault",
			Source:      source,
			Severity:    "pass",
			Description: "RuntimeDefault seccomp profile is applied from " + source + " level.",
		}
	case corev1.SeccompProfileTypeLocalhost:
		path := ""
		if profile.LocalhostProfile != nil {
			path = *profile.LocalhostProfile
		}
		return SeccompFinding{
			Container:   container,
			ProfileType: "Localhost",
			Source:      source,
			Severity:    "info",
			Description: "Localhost seccomp profile applied from " + source + " level: " + path,
			Remediation: "Ensure the localhost profile restricts syscalls appropriately",
		}
	case corev1.SeccompProfileTypeUnconfined:
		return SeccompFinding{
			Container:   container,
			ProfileType: "Unconfined",
			Source:      source,
			Severity:    "error",
			Description: "Unconfined seccomp profile explicitly set at " + source + " level.",
			Remediation: "Change seccompProfile.type to RuntimeDefault",
		}
	default:
		return SeccompFinding{
			Container:   container,
			ProfileType: string(profile.Type),
			Source:      source,
			Severity:    "warning",
			Description: "Unknown seccomp profile type: " + string(profile.Type),
		}
	}
}
