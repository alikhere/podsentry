package utils

import (
	corev1 "k8s.io/api/core/v1"
)

// PodName returns a displayable name for a pod, falling back to "<unnamed>"
// if the metadata name is empty.
func PodName(name string) string {
	if name == "" {
		return "<unnamed>"
	}
	return name
}

// PodNamespace returns the namespace or "default" if empty.
func PodNamespace(namespace string) string {
	if namespace == "" {
		return "default"
	}
	return namespace
}

// HasSecurityContext reports whether the spec has a non-nil pod-level security context.
func HasSecurityContext(spec *corev1.PodSpec) bool {
	return spec.SecurityContext != nil
}

// IsRunAsNonRoot reports whether the pod or container is configured to run as non-root.
func IsRunAsNonRoot(podSC *corev1.PodSecurityContext, containerSC *corev1.SecurityContext) bool {
	if containerSC != nil && containerSC.RunAsNonRoot != nil {
		return *containerSC.RunAsNonRoot
	}
	if podSC != nil && podSC.RunAsNonRoot != nil {
		return *podSC.RunAsNonRoot
	}
	return false
}
