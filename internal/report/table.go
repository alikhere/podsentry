package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/alikhere/podsentry/internal/pss"
	"github.com/alikhere/podsentry/internal/securitycontext"
	"github.com/alikhere/podsentry/internal/userns"
	"github.com/olekukonko/tablewriter"
)

// WritePSSTable writes PSS evaluation results as a formatted table.
func WritePSSTable(w io.Writer, results []pss.Result) {
	for _, r := range results {
		fmt.Fprintf(w, "\n%s  %s/%s  [%s]\n",
			PassFail(r.Pass),
			r.Namespace,
			r.Name,
			strings.ToUpper(string(r.Level)),
		)

		if r.Pass {
			colorPass.Fprintln(w, "  No violations found.")
			continue
		}

		table := tablewriter.NewWriter(w)
		table.SetHeader([]string{"ID", "Rule", "Container", "Severity", "Message"})
		table.SetBorder(false)
		table.SetColumnSeparator("  ")
		table.SetHeaderLine(false)
		table.SetAutoWrapText(true)
		table.SetColWidth(60)

		for _, v := range r.Violations {
			table.Append([]string{
				v.ID,
				v.Rule,
				v.Container,
				SeverityColor(string(v.Severity)),
				v.Message,
			})
		}
		table.Render()
	}
}

// WriteUserNSTable writes a user namespace inspection report as a table.
func WriteUserNSTable(w io.Writer, report *userns.Report) {
	fmt.Fprintf(w, "\nUser Namespace Report: %s/%s\n", report.Namespace, report.PodName)
	fmt.Fprintf(w, "hostUsers: %s\n\n", colorHeader.Sprint(string(report.HostUsers)))

	if len(report.Findings) > 0 {
		colorHeader.Fprintln(w, "Findings:")
		table := tablewriter.NewWriter(w)
		table.SetHeader([]string{"Field", "Status", "Severity", "Description"})
		table.SetBorder(false)
		table.SetColumnSeparator("  ")
		table.SetHeaderLine(false)
		table.SetAutoWrapText(true)
		table.SetColWidth(50)

		for _, f := range report.Findings {
			table.Append([]string{f.Field, f.Status, SeverityColor(f.Severity), f.Description})
		}
		table.Render()
	}

	if len(report.Implications) > 0 {
		fmt.Fprintln(w)
		colorHeader.Fprintln(w, "Security Implications:")
		for _, imp := range report.Implications {
			icon := colorError.Sprint("✗")
			if imp.Positive {
				icon = colorPass.Sprint("✓")
			}
			fmt.Fprintf(w, "  %s %s\n", icon, colorHeader.Sprint(imp.Title))
			colorMuted.Fprintf(w, "    %s\n\n", imp.Description)
		}
	}
}

// WriteSecCtxTable writes security context analysis results as a table.
func WriteSecCtxTable(w io.Writer, report *securitycontext.Report) {
	fmt.Fprintf(w, "\nSecurity Context Report: %s/%s\n\n", report.Namespace, report.PodName)

	colorHeader.Fprintln(w, "Capabilities:")
	capTable := tablewriter.NewWriter(w)
	capTable.SetHeader([]string{"Container", "Added", "Dropped", "Severity", "Description"})
	capTable.SetBorder(false)
	capTable.SetColumnSeparator("  ")
	capTable.SetHeaderLine(false)
	capTable.SetAutoWrapText(true)
	capTable.SetColWidth(40)
	for _, f := range report.Capabilities {
		capTable.Append([]string{
			f.Container,
			strings.Join(f.Added, ", "),
			strings.Join(f.Dropped, ", "),
			SeverityColor(f.Severity),
			f.Description,
		})
	}
	capTable.Render()

	fmt.Fprintln(w)
	colorHeader.Fprintln(w, "Privilege Settings:")
	privTable := tablewriter.NewWriter(w)
	privTable.SetHeader([]string{"Container", "Privileged", "AllowEscalation", "RunAsNonRoot", "Severity"})
	privTable.SetBorder(false)
	privTable.SetColumnSeparator("  ")
	privTable.SetHeaderLine(false)
	for _, f := range report.Privilege {
		privTable.Append([]string{
			f.Container,
			formatBool(f.Privileged),
			formatBoolPtr(f.AllowPrivilegeEscalation),
			formatBoolPtr(f.RunAsNonRoot),
			SeverityColor(f.Severity),
		})
	}
	privTable.Render()

	fmt.Fprintln(w)
	colorHeader.Fprintln(w, "Seccomp Profiles:")
	secTable := tablewriter.NewWriter(w)
	secTable.SetHeader([]string{"Container", "Profile", "Source", "Severity"})
	secTable.SetBorder(false)
	secTable.SetColumnSeparator("  ")
	secTable.SetHeaderLine(false)
	for _, f := range report.Seccomp {
		secTable.Append([]string{f.Container, f.ProfileType, f.Source, SeverityColor(f.Severity)})
	}
	secTable.Render()

	fmt.Fprintln(w)
	colorHeader.Fprintln(w, "Host Namespaces:")
	nsTable := tablewriter.NewWriter(w)
	nsTable.SetHeader([]string{"Field", "Enabled", "Severity", "Description"})
	nsTable.SetBorder(false)
	nsTable.SetColumnSeparator("  ")
	nsTable.SetHeaderLine(false)
	nsTable.SetAutoWrapText(true)
	nsTable.SetColWidth(50)
	for _, f := range report.HostNamespaces {
		nsTable.Append([]string{f.Field, formatBool(f.Value), SeverityColor(f.Severity), f.Description})
	}
	nsTable.Render()
}

func formatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func formatBoolPtr(b *bool) string {
	if b == nil {
		return "<unset>"
	}
	return formatBool(*b)
}
