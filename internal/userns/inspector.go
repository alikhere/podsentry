package userns

import (
	corev1 "k8s.io/api/core/v1"
)

// HostUsersStatus describes the effective user namespace configuration.
type HostUsersStatus string

const (
	StatusHostNamespace  HostUsersStatus = "host-namespace"
	StatusUserNamespace  HostUsersStatus = "user-namespace"
	StatusUnset          HostUsersStatus = "unset"
)

// Finding describes one observation about a pod's user namespace configuration.
type Finding struct {
	Field       string
	Status      string
	Severity    string
	Description string
	Remediation string
}

// Report holds the full user namespace inspection result for a pod.
type Report struct {
	PodName     string
	Namespace   string
	HostUsers   HostUsersStatus
	Findings    []Finding
	Implications []Implication
}

// Inspector examines a PodSpec for user namespace configuration.
type Inspector struct{}

// NewInspector creates a new Inspector.
func NewInspector() *Inspector {
	return &Inspector{}
}

// Inspect analyzes the user namespace configuration of the given PodSpec.
func (i *Inspector) Inspect(name, namespace string, spec *corev1.PodSpec) Report {
	status := resolveHostUsersStatus(spec)

	report := Report{
		PodName:   name,
		Namespace: namespace,
		HostUsers: status,
	}

	report.Findings = append(report.Findings, hostUsersFinding(spec, status))
	report.Findings = append(report.Findings, privilegedConflictFindings(spec, status)...)
	report.Implications = computeImplications(status)

	return report
}

func resolveHostUsersStatus(spec *corev1.PodSpec) HostUsersStatus {
	if spec.HostUsers == nil {
		return StatusUnset
	}
	if *spec.HostUsers {
		return StatusHostNamespace
	}
	return StatusUserNamespace
}

func hostUsersFinding(spec *corev1.PodSpec, status HostUsersStatus) Finding {
	switch status {
	case StatusUserNamespace:
		return Finding{
			Field:       "hostUsers",
			Status:      "false",
			Severity:    "info",
			Description: "Pod runs in a user namespace (hostUsers=false). UIDs/GIDs are remapped.",
			Remediation: "No action needed. This is the recommended setting for isolation.",
		}
	case StatusHostNamespace:
		return Finding{
			Field:       "hostUsers",
			Status:      "true",
			Severity:    "warning",
			Description: "Pod shares the host user namespace (hostUsers=true). Root in the pod is root on the host.",
			Remediation: "Set hostUsers: false to enable user namespace isolation",
		}
	default:
		return Finding{
			Field:       "hostUsers",
			Status:      "unset (defaults to true)",
			Severity:    "warning",
			Description: "hostUsers is not set; the pod defaults to sharing the host user namespace.",
			Remediation: "Explicitly set hostUsers: false to opt into user namespace isolation",
		}
	}
}
