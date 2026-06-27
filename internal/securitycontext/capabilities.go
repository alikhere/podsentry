package securitycontext

import (
	corev1 "k8s.io/api/core/v1"
)

// CapabilityFinding describes a finding about a container's Linux capabilities.
type CapabilityFinding struct {
	Container   string
	Added       []string
	Dropped     []string
	Severity    string
	Description string
	Remediation string
}

// AnalyzeCapabilities inspects capability settings for all containers in the spec.
func AnalyzeCapabilities(spec *corev1.PodSpec) []CapabilityFinding {
	var findings []CapabilityFinding

	for _, c := range allContainers(spec) {
		f := analyzeContainerCapabilities(c)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

func analyzeContainerCapabilities(c corev1.Container) *CapabilityFinding {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return &CapabilityFinding{
			Container:   c.Name,
			Severity:    "warning",
			Description: "No capabilities configuration. Container inherits default capabilities.",
			Remediation: "Explicitly set capabilities.drop: [ALL] and add only what is needed",
		}
	}

	caps := c.SecurityContext.Capabilities
	var added, dropped []string
	for _, cap := range caps.Add {
		added = append(added, string(cap))
	}
	for _, cap := range caps.Drop {
		dropped = append(dropped, string(cap))
	}

	dropsAll := false
	for _, d := range caps.Drop {
		if d == "ALL" {
			dropsAll = true
			break
		}
	}

	if len(added) == 0 && dropsAll {
		return &CapabilityFinding{
			Container:   c.Name,
			Added:       added,
			Dropped:     dropped,
			Severity:    "pass",
			Description: "Capabilities are minimized: drops ALL with no additions.",
			Remediation: "",
		}
	}

	severity := "info"
	desc := "Container modifies capabilities."
	remediation := ""

	if len(added) > 0 {
		severity = "warning"
		desc = "Container adds capabilities: " + joinStrings(added)
		remediation = "Review added capabilities and drop ALL unless specific caps are required"
	}

	if !dropsAll && len(added) > 0 {
		severity = "error"
		desc = "Container adds capabilities without dropping ALL first"
		remediation = "Add ALL to capabilities.drop and only re-add specific needed capabilities"
	}

	return &CapabilityFinding{
		Container:   c.Name,
		Added:       added,
		Dropped:     dropped,
		Severity:    severity,
		Description: desc,
		Remediation: remediation,
	}
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}
