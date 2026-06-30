package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/alikhere/podsentry/internal/pss"
)

// JSONEncoder wraps json.Encoder with pretty-print defaults.
type JSONEncoder struct {
	enc *json.Encoder
}

// NewJSONEncoder creates a JSONEncoder writing to w with indentation.
func NewJSONEncoder(w io.Writer) *JSONEncoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return &JSONEncoder{enc: enc}
}

// Encode writes v as indented JSON.
func (e *JSONEncoder) Encode(v any) error {
	return e.enc.Encode(v)
}

// WritePSSJSON writes PSS results as JSON to the given writer.
func WritePSSJSON(w io.Writer, results []pss.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		return fmt.Errorf("encoding PSS results as JSON: %w", err)
	}
	return nil
}

// WriteInspectJSON writes a combined inspect report as JSON.
func WriteInspectJSON(w io.Writer, reports []InspectReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(reports); err != nil {
		return fmt.Errorf("encoding inspect reports as JSON: %w", err)
	}
	return nil
}
