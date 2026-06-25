package userns

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestDefaultMapping(t *testing.T) {
	m := DefaultMapping()
	if m.ContainerID != 0 {
		t.Errorf("expected ContainerID 0, got %d", m.ContainerID)
	}
	if m.HostID != 65536 {
		t.Errorf("expected HostID 65536, got %d", m.HostID)
	}
	if m.Size != 65536 {
		t.Errorf("expected Size 65536, got %d", m.Size)
	}
}

func TestPrivilegedConflictNotInHostNamespace(t *testing.T) {
	spec := &corev1.PodSpec{
		HostUsers: boolPtr(true),
		Containers: []corev1.Container{
			{
				Name: "priv",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			},
		},
	}
	findings := privilegedConflictFindings(spec, StatusHostNamespace)
	if len(findings) != 0 {
		t.Errorf("expected no conflict findings in host namespace, got %d", len(findings))
	}
}

func TestPrivilegedConflictInUserNamespace(t *testing.T) {
	spec := &corev1.PodSpec{
		HostUsers: boolPtr(false),
		Containers: []corev1.Container{
			{
				Name: "priv",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			},
		},
	}
	findings := privilegedConflictFindings(spec, StatusUserNamespace)
	if len(findings) != 1 {
		t.Errorf("expected 1 conflict finding, got %d", len(findings))
	}
}
