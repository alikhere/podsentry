package pss

import (
	corev1 "k8s.io/api/core/v1"
)

// restrictedRules returns all rules enforcing the Restricted PSS level.
// Restricted rules are additive on top of Baseline rules.
func restrictedRules() []Rule {
	var rules []Rule
	rules = append(rules, baselineRules()...)
	rules = append(rules,
		&restrictedVolumeTypesRule{},
		&restrictedPrivilegeEscalationRule{},
		&restrictedRunAsNonRootRule{},
		&restrictedCapabilitiesRule{},
		&restrictedSeccompRule{},
	)
	return rules
}

var restrictedAllowedVolumeTypes = map[corev1.VolumeSource]bool{}

func isRestrictedVolumeAllowed(v corev1.Volume) bool {
	src := v.VolumeSource
	return src.ConfigMap != nil ||
		src.EmptyDir != nil ||
		src.PersistentVolumeClaim != nil ||
		src.Projected != nil ||
		src.Secret != nil ||
		src.CSI != nil ||
		src.Ephemeral != nil ||
		src.DownwardAPI != nil
}

type restrictedVolumeTypesRule struct{}

func (r *restrictedVolumeTypesRule) ID() string    { return "PSS-RS-001" }
func (r *restrictedVolumeTypesRule) Name() string  { return "Restricted Volume Types" }
func (r *restrictedVolumeTypesRule) Level() Level  { return LevelRestricted }

func (r *restrictedVolumeTypesRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	for _, v := range spec.Volumes {
		if !isRestrictedVolumeAllowed(v) {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "volume type not allowed under restricted policy: " + v.Name,
				Remediation: "Use only configMap, emptyDir, secret, projected, PVC, CSI, or downwardAPI volumes",
			})
		}
	}
	return violations
}

type restrictedPrivilegeEscalationRule struct{}

func (r *restrictedPrivilegeEscalationRule) ID() string    { return "PSS-RS-002" }
func (r *restrictedPrivilegeEscalationRule) Name() string  { return "Privilege Escalation" }
func (r *restrictedPrivilegeEscalationRule) Level() Level  { return LevelRestricted }

func (r *restrictedPrivilegeEscalationRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	for _, c := range allContainers(spec) {
		if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "allowPrivilegeEscalation must be explicitly set to false",
				Container:   c.Name,
				Remediation: "Set securityContext.allowPrivilegeEscalation: false",
			})
		}
	}
	return violations
}

type restrictedRunAsNonRootRule struct{}

func (r *restrictedRunAsNonRootRule) ID() string    { return "PSS-RS-003" }
func (r *restrictedRunAsNonRootRule) Name() string  { return "Running as Non-Root" }
func (r *restrictedRunAsNonRootRule) Level() Level  { return LevelRestricted }

func (r *restrictedRunAsNonRootRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation

	podRunAsNonRoot := spec.SecurityContext != nil &&
		spec.SecurityContext.RunAsNonRoot != nil &&
		*spec.SecurityContext.RunAsNonRoot

	podRunAsUser := spec.SecurityContext != nil && spec.SecurityContext.RunAsUser != nil

	for _, c := range allContainers(spec) {
		containerRunAsNonRoot := c.SecurityContext != nil &&
			c.SecurityContext.RunAsNonRoot != nil &&
			*c.SecurityContext.RunAsNonRoot

		containerRunAsUserSet := c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil

		effectiveRunAsNonRoot := podRunAsNonRoot || containerRunAsNonRoot

		if !effectiveRunAsNonRoot {
			if containerRunAsUserSet && *c.SecurityContext.RunAsUser != 0 {
				continue
			}
			if !containerRunAsUserSet && podRunAsUser && *spec.SecurityContext.RunAsUser != 0 {
				continue
			}
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "runAsNonRoot must be true at pod or container level",
				Container:   c.Name,
				Remediation: "Set securityContext.runAsNonRoot: true or securityContext.runAsUser to a non-zero value",
			})
		}

		if containerRunAsUserSet && *c.SecurityContext.RunAsUser == 0 {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "runAsUser must not be 0",
				Container:   c.Name,
				Remediation: "Set securityContext.runAsUser to a non-zero UID",
			})
		}
	}

	if spec.SecurityContext != nil && spec.SecurityContext.RunAsUser != nil && *spec.SecurityContext.RunAsUser == 0 {
		violations = append(violations, Violation{
			ID:          r.ID(),
			Rule:        r.Name(),
			Severity:    SeverityError,
			Message:     "pod-level runAsUser must not be 0",
			Remediation: "Set pod securityContext.runAsUser to a non-zero UID",
		})
	}

	return violations
}

type restrictedCapabilitiesRule struct{}

func (r *restrictedCapabilitiesRule) ID() string    { return "PSS-RS-004" }
func (r *restrictedCapabilitiesRule) Name() string  { return "Capabilities (Restricted)" }
func (r *restrictedCapabilitiesRule) Level() Level  { return LevelRestricted }

func (r *restrictedCapabilitiesRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation
	for _, c := range allContainers(spec) {
		if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "capabilities must explicitly drop ALL",
				Container:   c.Name,
				Remediation: "Set securityContext.capabilities.drop: [ALL]",
			})
			continue
		}

		dropsAll := false
		for _, d := range c.SecurityContext.Capabilities.Drop {
			if d == "ALL" {
				dropsAll = true
				break
			}
		}
		if !dropsAll {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "capabilities must drop ALL",
				Container:   c.Name,
				Remediation: "Add ALL to securityContext.capabilities.drop",
			})
		}

		for _, cap := range c.SecurityContext.Capabilities.Add {
			if cap != "NET_BIND_SERVICE" {
				violations = append(violations, Violation{
					ID:          r.ID(),
					Rule:        r.Name(),
					Severity:    SeverityError,
					Message:     "only NET_BIND_SERVICE may be added under restricted policy, got " + string(cap),
					Container:   c.Name,
					Remediation: "Remove all added capabilities except NET_BIND_SERVICE",
				})
			}
		}
	}
	return violations
}

type restrictedSeccompRule struct{}

func (r *restrictedSeccompRule) ID() string    { return "PSS-RS-005" }
func (r *restrictedSeccompRule) Name() string  { return "Seccomp Profile" }
func (r *restrictedSeccompRule) Level() Level  { return LevelRestricted }

func (r *restrictedSeccompRule) Check(spec *corev1.PodSpec) []Violation {
	var violations []Violation

	podSeccomp := spec.SecurityContext != nil && spec.SecurityContext.SeccompProfile != nil

	for _, c := range allContainers(spec) {
		containerSeccomp := c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil

		if containerSeccomp {
			t := c.SecurityContext.SeccompProfile.Type
			if t != corev1.SeccompProfileTypeRuntimeDefault && t != corev1.SeccompProfileTypeLocalhost {
				violations = append(violations, Violation{
					ID:          r.ID(),
					Rule:        r.Name(),
					Severity:    SeverityError,
					Message:     "seccomp profile type must be RuntimeDefault or Localhost",
					Container:   c.Name,
					Remediation: "Set securityContext.seccompProfile.type to RuntimeDefault or Localhost",
				})
			}
			continue
		}

		if !podSeccomp {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "seccomp profile must be set to RuntimeDefault or Localhost at pod or container level",
				Container:   c.Name,
				Remediation: "Set securityContext.seccompProfile.type to RuntimeDefault at pod level",
			})
			continue
		}

		t := spec.SecurityContext.SeccompProfile.Type
		if t != corev1.SeccompProfileTypeRuntimeDefault && t != corev1.SeccompProfileTypeLocalhost {
			violations = append(violations, Violation{
				ID:          r.ID(),
				Rule:        r.Name(),
				Severity:    SeverityError,
				Message:     "pod-level seccomp profile type must be RuntimeDefault or Localhost",
				Remediation: "Set pod securityContext.seccompProfile.type to RuntimeDefault",
			})
		}
	}

	return violations
}
