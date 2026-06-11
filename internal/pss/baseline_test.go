package pss

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func boolPtr(b bool) *bool { return &b }

func int64Ptr(i int64) *int64 { return &i }

func TestBaselinePrivilegedRule(t *testing.T) {
	r := &baselinePrivilegedRule{}

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "privileged",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			},
		},
	}
	violations := r.Check(spec)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Container != "privileged" {
		t.Errorf("expected container name 'privileged', got %q", violations[0].Container)
	}
}

func TestBaselinePrivilegedRulePass(t *testing.T) {
	r := &baselinePrivilegedRule{}

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "app", SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(false)}},
		},
	}
	violations := r.Check(spec)
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestBaselineHostNamespacesRule(t *testing.T) {
	r := &baselineHostNamespacesRule{}

	spec := &corev1.PodSpec{
		HostNetwork: true,
		HostPID:     true,
		HostIPC:     true,
	}
	violations := r.Check(spec)
	if len(violations) != 3 {
		t.Errorf("expected 3 violations, got %d", len(violations))
	}
}

func TestBaselineHostPathVolumesRule(t *testing.T) {
	r := &baselineHostPathVolumesRule{}

	spec := &corev1.PodSpec{
		Volumes: []corev1.Volume{
			{
				Name:         "host-vol",
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/tmp"}},
			},
		},
	}
	violations := r.Check(spec)
	if len(violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(violations))
	}
}

func TestBaselineCapabilitiesRule(t *testing.T) {
	r := &baselineCapabilitiesRule{}

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"SYS_ADMIN"},
					},
				},
			},
		},
	}
	violations := r.Check(spec)
	if len(violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(violations))
	}
}

func TestBaselineCapabilitiesRuleAllowed(t *testing.T) {
	r := &baselineCapabilitiesRule{}

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"NET_BIND_SERVICE"},
					},
				},
			},
		},
	}
	violations := r.Check(spec)
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}
