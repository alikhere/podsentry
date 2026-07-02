package utils

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAllContainers(t *testing.T) {
	spec := &corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init"}},
		Containers:     []corev1.Container{{Name: "main"}, {Name: "sidecar"}},
	}
	all := AllContainers(spec)
	if len(all) != 3 {
		t.Fatalf("expected 3 containers, got %d", len(all))
	}
	if all[0].Name != "init" {
		t.Errorf("expected first container to be init, got %s", all[0].Name)
	}
}

func TestContainerByName(t *testing.T) {
	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "app"},
			{Name: "sidecar"},
		},
		InitContainers: []corev1.Container{
			{Name: "init"},
		},
	}

	c := ContainerByName(spec, "app")
	if c == nil || c.Name != "app" {
		t.Error("expected to find 'app' container")
	}

	c = ContainerByName(spec, "init")
	if c == nil || c.Name != "init" {
		t.Error("expected to find 'init' container")
	}

	c = ContainerByName(spec, "missing")
	if c != nil {
		t.Error("expected nil for missing container")
	}
}

func TestHasHostPorts(t *testing.T) {
	spec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				Ports: []corev1.ContainerPort{
					{ContainerPort: 8080, HostPort: 8080},
				},
			},
		},
	}
	if !HasHostPorts(spec) {
		t.Error("expected HasHostPorts to return true")
	}

	spec.Containers[0].Ports[0].HostPort = 0
	if HasHostPorts(spec) {
		t.Error("expected HasHostPorts to return false")
	}
}
