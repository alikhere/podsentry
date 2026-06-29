package securitycontext

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAnalyzeCapabilitiesNoConfig(t *testing.T) {
	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "app"},
		},
	}
	findings := AnalyzeCapabilities(spec)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "warning" {
		t.Errorf("expected warning severity, got %s", findings[0].Severity)
	}
}

func TestAnalyzeCapabilitiesDropAll(t *testing.T) {
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
	findings := AnalyzeCapabilities(spec)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "pass" {
		t.Errorf("expected pass severity, got %s", findings[0].Severity)
	}
}

func TestAnalyzeCapabilitiesAddWithoutDrop(t *testing.T) {
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
	findings := AnalyzeCapabilities(spec)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "error" {
		t.Errorf("expected error severity for add without drop ALL, got %s", findings[0].Severity)
	}
}
