package pss

import (
	corev1 "k8s.io/api/core/v1"
)

// defaultAllowedCapabilities is the set of Linux capabilities permitted under
// the Baseline PSS level, matching the upstream Kubernetes definition.
var defaultAllowedCapabilities = map[corev1.Capability]struct{}{
	"AUDIT_WRITE":  {},
	"CHOWN":        {},
	"DAC_OVERRIDE": {},
	"FOWNER":       {},
	"FSETID":       {},
	"KILL":         {},
	"MKNOD":        {},
	"NET_BIND_SERVICE": {},
	"SETFCAP":      {},
	"SETGID":       {},
	"SETPCAP":      {},
	"SETUID":       {},
	"SYS_CHROOT":   {},
}

// baselineRules returns all rules that enforce the Baseline PSS level.
func baselineRules() []Rule {
	return []Rule{
		&baselinePrivilegedRule{},
		&baselineHostNamespacesRule{},
		&baselineHostPathVolumesRule{},
		&baselineHostPortsRule{},
		&baselineCapabilitiesRule{},
		&baselineProcMountRule{},
		&baselineSysctlsRule{},
	}
}

type baselinePrivilegedRule struct{}

func (r *baselinePrivilegedRule) ID() string    { return "PSS-BL-001" }
func (r *baselinePrivilegedRule) Name() string  { return "Privileged Containers" }
func (r *baselinePrivilegedRule) Level() Level  { return LevelBaseline }

func (r *baselinePrivilegedRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	for _, c := range allContainers(spec) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "privileged mode is not allowed",
				Container:   c.Name,
				Remediation: "Set securityContext.privileged to false or remove the field",
			})
		}
	}
	return violations
}

type baselineHostNamespacesRule struct{}

func (r *baselineHostNamespacesRule) ID() string    { return "PSS-BL-002" }
func (r *baselineHostNamespacesRule) Name() string  { return "Host Namespaces" }
func (r *baselineHostNamespacesRule) Level() Level  { return LevelBaseline }

func (r *baselineHostNamespacesRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	if spec.HostNetwork {
		violations = append(violations, Violation{
			ID:          r.ID(),
			Rule:        r.Name(),
			Severity:    SeverityError,
			Message:     "hostNetwork must not be true",
			Remediation: "Set hostNetwork to false or remove the field",
		})
	}
	if spec.HostPID {
		violations = append(violations, Violation{
			ID:          r.ID(),
			Rule:        r.Name(),
			Severity:    SeverityError,
			Message:     "hostPID must not be true",
			Remediation: "Set hostPID to false or remove the field",
		})
	}
	if spec.HostIPC {
		violations = append(violations, Violation{
			ID:          r.ID(),
			Rule:        r.Name(),
			Severity:    SeverityError,
			Message:     "hostIPC must not be true",
			Remediation: "Set hostIPC to false or remove the field",
		})
	}
	return violations
}

type baselineHostPathVolumesRule struct{}

func (r *baselineHostPathVolumesRule) ID() string    { return "PSS-BL-003" }
func (r *baselineHostPathVolumesRule) Name() string  { return "HostPath Volumes" }
func (r *baselineHostPathVolumesRule) Level() Level  { return LevelBaseline }

func (r *baselineHostPathVolumesRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "HostPath volumes are not allowed: " + v.Name,
				Remediation: "Replace HostPath volumes with emptyDir, configMap, secret, or PVC",
			})
		}
	}
	return violations
}

type baselineHostPortsRule struct{}

func (r *baselineHostPortsRule) ID() string    { return "PSS-BL-004" }
func (r *baselineHostPortsRule) Name() string  { return "Host Ports" }
func (r *baselineHostPortsRule) Level() Level  { return LevelBaseline }

func (r *baselineHostPortsRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	for _, c := range allContainers(spec) {
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				violations = append(violations, Violation{
					ID:          r.ID(),
					Rule:        r.Name(),
					Severity:    SeverityError,
					Message:     "host ports are not allowed",
					Container:   c.Name,
					Remediation: "Remove hostPort from container port definitions",
				})
			}
		}
	}
	return violations
}

type baselineCapabilitiesRule struct{}

func (r *baselineCapabilitiesRule) ID() string    { return "PSS-BL-005" }
func (r *baselineCapabilitiesRule) Name() string  { return "Capabilities" }
func (r *baselineCapabilitiesRule) Level() Level  { return LevelBaseline }

func (r *baselineCapabilitiesRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	for _, c := range allContainers(spec) {
		if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
			continue
		}
		for _, cap := range c.SecurityContext.Capabilities.Add {
			if _, allowed := defaultAllowedCapabilities[cap]; !allowed {
				violations = append(violations, Violation{
					ID:          r.ID(),
					Rule:        r.Name(),
					Severity:    SeverityError,
					Message:     "capability " + string(cap) + " is not in the baseline allowed set",
					Container:   c.Name,
					Remediation: "Remove non-baseline capabilities from securityContext.capabilities.add",
				})
			}
		}
	}
	return violations
}

type baselineProcMountRule struct{}

func (r *baselineProcMountRule) ID() string    { return "PSS-BL-006" }
func (r *baselineProcMountRule) Name() string  { return "Proc Mount" }
func (r *baselineProcMountRule) Level() Level  { return LevelBaseline }

func (r *baselineProcMountRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	for _, c := range allContainers(spec) {
		if c.SecurityContext == nil {
			continue
		}
		if c.SecurityContext.ProcMount != nil && *c.SecurityContext.ProcMount != corev1.DefaultProcMount {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "non-default procMount type is not allowed",
				Container:   c.Name,
				Remediation: "Remove securityContext.procMount or set it to Default",
			})
		}
	}
	return violations
}

var allowedSysctls = map[string]struct{}{
	"kernel.shm_rmid_forced":              {},
	"net.ipv4.ip_local_port_range":        {},
	"net.ipv4.ip_unprivileged_port_start": {},
	"net.ipv4.tcp_syncookies":             {},
	"net.ipv4.ping_group_range":           {},
}

type baselineSysctlsRule struct{}

func (r *baselineSysctlsRule) ID() string    { return "PSS-BL-007" }
func (r *baselineSysctlsRule) Name() string  { return "Sysctls" }
func (r *baselineSysctlsRule) Level() Level  { return LevelBaseline }

func (r *baselineSysctlsRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	if spec.SecurityContext == nil {
		return violations
	}
	for _, s := range spec.SecurityContext.Sysctls {
		if _, allowed := allowedSysctls[s.Name]; !allowed {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "sysctl " + s.Name + " is not in the safe sysctls list",
				Remediation: "Remove unsafe sysctls from securityContext.sysctls",
			})
		}
	}
	return violations
}

func allContainers(spec *corev1.PodSpec) []corev1.Container {
	containers := make([]corev1.Container, 0, len(spec.Containers)+len(spec.InitContainers))
	containers = append(containers, spec.Containers...)
	containers = append(containers, spec.InitContainers...)
	return containers
}
