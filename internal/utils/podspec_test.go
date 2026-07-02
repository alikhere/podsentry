package utils

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func boolPtr(b bool) *bool { return &b }

func TestPodName(t *testing.T) {
	if PodName("nginx") != "nginx" {
		t.Error("expected 'nginx'")
	}
	if PodName("") != "<unnamed>" {
		t.Error("expected '<unnamed>' for empty name")
	}
}

func TestPodNamespace(t *testing.T) {
	if PodNamespace("production") != "production" {
		t.Error("expected 'production'")
	}
	if PodNamespace("") != "default" {
		t.Error("expected 'default' for empty namespace")
	}
}

func TestIsRunAsNonRoot(t *testing.T) {
	cases := []struct {
		podSC       *corev1.PodSecurityContext
		containerSC *corev1.SecurityContext
		want        bool
	}{
		{nil, nil, false},
		{
			&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)},
			nil,
			true,
		},
		{
			nil,
			&corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			true,
		},
		{
			&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)},
			&corev1.SecurityContext{RunAsNonRoot: boolPtr(false)},
			false,
		},
	}
	for _, c := range cases {
		got := IsRunAsNonRoot(c.podSC, c.containerSC)
		if got != c.want {
			t.Errorf("IsRunAsNonRoot() = %v, want %v", got, c.want)
		}
	}
}
