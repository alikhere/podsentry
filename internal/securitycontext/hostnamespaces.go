package securitycontext

import (
	corev1 "k8s.io/api/core/v1"
)

// HostNamespaceFinding describes findings about host namespace usage.
type HostNamespaceFinding struct {
	Field       string
	Value       bool
	Severity    string
	Description string
	Remediation string
}

// AnalyzeHostNamespaces inspects host namespace configuration in the PodSpec.
func AnalyzeHostNamespaces(spec *corev1.PodSpec) []HostNamespaceFinding {
	var findings []HostNamespaceFinding

	findings = append(findings, HostNamespaceFinding{
		Field:       "hostNetwork",
		Value:       spec.HostNetwork,
		Severity:    hostNSSeverity(spec.HostNetwork),
		Description: hostNetworkDescription(spec.HostNetwork),
		Remediation: "Set hostNetwork: false or remove the field",
	})

	findings = append(findings, HostNamespaceFinding{
		Field:       "hostPID",
		Value:       spec.HostPID,
		Severity:    hostNSSeverity(spec.HostPID),
		Description: hostPIDDescription(spec.HostPID),
		Remediation: "Set hostPID: false or remove the field",
	})

	findings = append(findings, HostNamespaceFinding{
		Field:       "hostIPC",
		Value:       spec.HostIPC,
		Severity:    hostNSSeverity(spec.HostIPC),
		Description: hostIPCDescription(spec.HostIPC),
		Remediation: "Set hostIPC: false or remove the field",
	})

	for _, c := range allContainers(spec) {
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				findings = append(findings, HostNamespaceFinding{
					Field:       "containers[" + c.Name + "].ports.hostPort",
					Value:       true,
					Severity:    "warning",
					Description: "Host port binding detected on container " + c.Name,
					Remediation: "Remove hostPort and use a Service with nodePort if needed",
				})
			}
		}
	}

	return findings
}

func hostNSSeverity(enabled bool) string {
	if enabled {
		return "error"
	}
	return "pass"
}

func hostNetworkDescription(enabled bool) string {
	if enabled {
		return "hostNetwork is true. Container shares the host network stack; all host ports are accessible."
	}
	return "hostNetwork is false. Container uses its own network namespace."
}

func hostPIDDescription(enabled bool) string {
	if enabled {
		return "hostPID is true. Container can see and signal all host processes."
	}
	return "hostPID is false. Container has an isolated PID namespace."
}

func hostIPCDescription(enabled bool) string {
	if enabled {
		return "hostIPC is true. Container can access host IPC resources including shared memory."
	}
	return "hostIPC is false. Container has an isolated IPC namespace."
}
