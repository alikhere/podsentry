package userns

// Implication describes a security consequence of the current user namespace configuration.
type Implication struct {
	Title       string
	Description string
	Positive    bool
}

func computeImplications(status HostUsersStatus) []Implication {
	switch status {
	case StatusUserNamespace:
		return []Implication{
			{
				Title:       "UID Remapping Active",
				Description: "Container UID 0 maps to an unprivileged host UID. Root inside the container has no host-level privileges.",
				Positive:    true,
			},
			{
				Title:       "Reduced Kernel Attack Surface",
				Description: "User namespace isolation limits the syscalls available to container processes, reducing kernel exploit impact.",
				Positive:    true,
			},
			{
				Title:       "Volume Permission Compatibility",
				Description: "Remapped UIDs may cause permission errors on host-mounted volumes. Ensure volume ownership matches remapped UIDs.",
				Positive:    false,
			},
		}
	case StatusHostNamespace, StatusUnset:
		return []Implication{
			{
				Title:       "Host UID Exposure",
				Description: "Processes in the container run with the same UIDs as on the host. A container breakout grants full host user access.",
				Positive:    false,
			},
			{
				Title:       "No UID Remapping",
				Description: "Container UID 0 is host UID 0. Any privilege escalation in the container directly affects the host.",
				Positive:    false,
			},
			{
				Title:       "Full syscall Surface",
				Description: "Without user namespace isolation, container processes have access to the full host kernel syscall surface.",
				Positive:    false,
			},
		}
	default:
		return nil
	}
}
