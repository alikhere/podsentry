package pss

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestNewEvaluatorUnknownLevel(t *testing.T) {
	_, err := NewEvaluator("unknown")
	if err == nil {
		t.Error("expected error for unknown level, got nil")
	}
}

func TestEvaluatorPrivileged(t *testing.T) {
	ev, err := NewEvaluator(LevelPrivileged)
	if err != nil {
		t.Fatal(err)
	}

	spec := &corev1.PodSpec{
		HostNetwork: true,
		Containers: []corev1.Container{
			{
				Name: "priv",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			},
		},
	}
	result := ev.Evaluate("test", "default", spec)
	if !result.Pass {
		t.Error("privileged level should pass everything")
	}
}

func TestEvaluatorBaselineViolations(t *testing.T) {
	ev, err := NewEvaluator(LevelBaseline)
	if err != nil {
		t.Fatal(err)
	}

	spec := &corev1.PodSpec{
		HostNetwork: true,
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			},
		},
	}
	result := ev.Evaluate("test", "default", spec)
	if result.Pass {
		t.Error("expected evaluation to fail")
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations")
	}
}

func TestEvaluatorRestrictedCleanPod(t *testing.T) {
	ev, err := NewEvaluator(LevelRestricted)
	if err != nil {
		t.Fatal(err)
	}

	allowEsc := false
	nonRoot := true
	uid := int64(1000)
	spec := &corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: &nonRoot,
			RunAsUser:    &uid,
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &allowEsc,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
				},
			},
		},
	}
	result := ev.Evaluate("clean", "default", spec)
	if !result.Pass {
		t.Errorf("expected pass for clean restricted pod, got %d violations", len(result.Violations))
		for _, v := range result.Violations {
			t.Logf("  violation: %s - %s", v.ID, v.Message)
		}
	}
}
