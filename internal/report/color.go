package report

import (
	"os"

	"github.com/fatih/color"
)

var (
	colorError   = color.New(color.FgRed, color.Bold)
	colorWarning = color.New(color.FgYellow, color.Bold)
	colorPass    = color.New(color.FgGreen, color.Bold)
	colorInfo    = color.New(color.FgCyan)
	colorHeader  = color.New(color.FgWhite, color.Bold)
	colorMuted   = color.New(color.FgHiBlack)
)

func init() {
	if !isTTY() {
		color.NoColor = true
	}
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// SeverityColor returns the colored string for a severity label.
func SeverityColor(severity string) string {
	switch severity {
	case "error":
		return colorError.Sprint("ERROR")
	case "warning":
		return colorWarning.Sprint("WARN ")
	case "pass":
		return colorPass.Sprint("PASS ")
	case "info":
		return colorInfo.Sprint("INFO ")
	default:
		return colorMuted.Sprint(severity)
	}
}

// PassFail returns a colored PASS or FAIL string.
func PassFail(pass bool) string {
	if pass {
		return colorPass.Sprint("PASS")
	}
	return colorError.Sprint("FAIL")
}
