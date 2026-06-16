package pss

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestRestrictedPrivilegeEscalationRule(t *testing.T) {
	r := &restrictedPrivilegeEscalationRule{}

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "app"},
		},
	}
	violations := r.Check(spec)
	if len(violations) == 0 {
		t.Error("expected violations for missing allowPrivilegeEscalation, got none")
	}

	spec.Containers[0].SecurityContext = &corev1.SecurityContext{
		AllowPrivilegeEscalation: boolPtr(false),
	}
	violations = r.Check(spec)
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestRestrictedRunAsNonRootRule(t *testing.T) {
	r := &restrictedRunAsNonRootRule{}

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "app"},
		},
	}
	violations := r.Check(spec)
	if len(violations) == 0 {
		t.Error("expected violations for missing runAsNonRoot, got none")
	}

	spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot: boolPtr(true),
	}
	violations = r.Check(spec)
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestRestrictedCapabilitiesRule(t *testing.T) {
	r := &restrictedCapabilitiesRule{}

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
			},
		},
	}
	violations := r.Check(spec)
	if len(violations) != 0 {
		t.Errorf("expected no violations for drop ALL, got %d", len(violations))
	}

	spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
	violations = r.Check(spec)
	if len(violations) == 0 {
		t.Error("expected violation for disallowed capability add")
	}
}

func TestRestrictedSeccompRule(t *testing.T) {
	r := &restrictedSeccompRule{}

	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "app"},
		},
	}
	violations := r.Check(spec)
	if len(violations) == 0 {
		t.Error("expected violations for missing seccomp profile, got none")
	}

	spec.SecurityContext = &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
	violations = r.Check(spec)
	if len(violations) != 0 {
		t.Errorf("expected no violations with RuntimeDefault seccomp, got %d", len(violations))
	}
}

func TestRestrictedVolumeTypesRule(t *testing.T) {
	r := &restrictedVolumeTypesRule{}

	spec := &corev1.PodSpec{
		Volumes: []corev1.Volume{
			{
				Name:         "host-vol",
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data"}},
			},
		},
	}
	violations := r.Check(spec)
	if len(violations) == 0 {
		t.Error("expected violation for hostPath volume under restricted policy")
	}

	spec.Volumes = []corev1.Volume{
		{
			Name:         "secret-vol",
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "my-secret"}},
		},
	}
	violations = r.Check(spec)
	if len(violations) != 0 {
		t.Errorf("expected no violations for secret volume, got %d", len(violations))
	}
}
