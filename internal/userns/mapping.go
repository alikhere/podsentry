package userns

import corev1 "k8s.io/api/core/v1"

// UIDMapping represents a UID/GID remapping for user namespaces.
type UIDMapping struct {
	ContainerID int64
	HostID      int64
	Size        int64
}

// DefaultMapping returns the typical user namespace UID mapping Kubernetes
// uses when hostUsers is false. The values reflect the kubelet defaults.
func DefaultMapping() UIDMapping {
	return UIDMapping{
		ContainerID: 0,
		HostID:      65536,
		Size:        65536,
	}
}

// privilegedConflictFindings returns warnings when privileged containers
// are combined with user namespace isolation, which the kernel disallows.
func privilegedConflictFindings(spec *corev1.PodSpec, status HostUsersStatus) []Finding {
	if status != StatusUserNamespace {
		return nil
	}

	var findings []Finding
	for _, c := range spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			findings = append(findings, Finding{
				Field:       "containers[" + c.Name + "].securityContext.privileged",
				Status:      "true",
				Severity:    "error",
				Description: "Privileged containers cannot run inside a user namespace. This configuration will be rejected by the kubelet.",
				Remediation: "Remove privileged: true or set hostUsers: true (not recommended)",
			})
		}
	}
	return findings
}
