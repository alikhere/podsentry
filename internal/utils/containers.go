package utils

import (
	corev1 "k8s.io/api/core/v1"
)

// AllContainers returns all init and regular containers from a PodSpec.
func AllContainers(spec *corev1.PodSpec) []corev1.Container {
	out := make([]corev1.Container, 0, len(spec.Containers)+len(spec.InitContainers))
	out = append(out, spec.InitContainers...)
	out = append(out, spec.Containers...)
	return out
}

// ContainerByName finds a container in the spec by name, returning nil if not found.
func ContainerByName(spec *corev1.PodSpec, name string) *corev1.Container {
	for i := range spec.Containers {
		if spec.Containers[i].Name == name {
			return &spec.Containers[i]
		}
	}
	for i := range spec.InitContainers {
		if spec.InitContainers[i].Name == name {
			return &spec.InitContainers[i]
		}
	}
	return nil
}

// HasHostPorts reports whether any container in the spec declares a host port.
func HasHostPorts(spec *corev1.PodSpec) bool {
	for _, c := range AllContainers(spec) {
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				return true
			}
		}
	}
	return false
}
