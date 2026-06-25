package userns

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func boolPtr(b bool) *bool { return &b }

func TestInspectHostUsersTrue(t *testing.T) {
	i := NewInspector()
	spec := &corev1.PodSpec{
		HostUsers: boolPtr(true),
	}
	report := i.Inspect("pod", "default", spec)
	if report.HostUsers != StatusHostNamespace {
		t.Errorf("expected host-namespace status, got %s", report.HostUsers)
	}
}

func TestInspectHostUsersFalse(t *testing.T) {
	i := NewInspector()
	spec := &corev1.PodSpec{
		HostUsers: boolPtr(false),
	}
	report := i.Inspect("pod", "default", spec)
	if report.HostUsers != StatusUserNamespace {
		t.Errorf("expected user-namespace status, got %s", report.HostUsers)
	}
}

func TestInspectHostUsersUnset(t *testing.T) {
	i := NewInspector()
	spec := &corev1.PodSpec{}
	report := i.Inspect("pod", "default", spec)
	if report.HostUsers != StatusUnset {
		t.Errorf("expected unset status, got %s", report.HostUsers)
	}
}

func TestInspectPrivilegedConflict(t *testing.T) {
	i := NewInspector()
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
	report := i.Inspect("pod", "default", spec)

	hasConflict := false
	for _, f := range report.Findings {
		if f.Severity == "error" {
			hasConflict = true
			break
		}
	}
	if !hasConflict {
		t.Error("expected error finding for privileged + user namespace conflict")
	}
}

func TestInspectImplicationsUserNamespace(t *testing.T) {
	i := NewInspector()
	spec := &corev1.PodSpec{HostUsers: boolPtr(false)}
	report := i.Inspect("pod", "default", spec)
	if len(report.Implications) == 0 {
		t.Error("expected implications for user namespace config")
	}
	for _, imp := range report.Implications {
		if imp.Positive && imp.Title == "UID Remapping Active" {
			return
		}
	}
	t.Error("expected UID Remapping Active implication")
}
