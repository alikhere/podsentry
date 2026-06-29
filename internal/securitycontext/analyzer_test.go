package securitycontext

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func boolPtr(b bool) *bool { return &b }

func TestAnalyzeFullSpec(t *testing.T) {
	a := NewAnalyzer()

	spec := &corev1.PodSpec{
		HostNetwork: true,
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(false),
					AllowPrivilegeEscalation: boolPtr(false),
					RunAsNonRoot: boolPtr(true),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
			},
		},
	}

	report := a.Analyze("test-pod", "default", spec)
	if report.PodName != "test-pod" {
		t.Errorf("expected pod name 'test-pod', got %q", report.PodName)
	}
	if len(report.Capabilities) == 0 {
		t.Error("expected capability findings")
	}
	if len(report.Privilege) == 0 {
		t.Error("expected privilege findings")
	}
	if len(report.Seccomp) == 0 {
		t.Error("expected seccomp findings")
	}
	if len(report.HostNamespaces) == 0 {
		t.Error("expected host namespace findings")
	}

	hasHostNetworkError := false
	for _, f := range report.HostNamespaces {
		if f.Field == "hostNetwork" && f.Severity == "error" {
			hasHostNetworkError = true
		}
	}
	if !hasHostNetworkError {
		t.Error("expected hostNetwork error finding")
	}
}

func TestAnalyzeSeccompNoProfile(t *testing.T) {
	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "app"},
		},
	}
	findings := AnalyzeSeccomp(spec)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "error" {
		t.Errorf("expected error for no seccomp profile, got %s", findings[0].Severity)
	}
}

func TestAnalyzeHostNamespacesClean(t *testing.T) {
	spec := &corev1.PodSpec{
		HostNetwork: false,
		HostPID:     false,
		HostIPC:     false,
	}
	findings := AnalyzeHostNamespaces(spec)
	for _, f := range findings {
		if f.Severity == "error" {
			t.Errorf("unexpected error finding for clean spec: %s", f.Field)
		}
	}
}
