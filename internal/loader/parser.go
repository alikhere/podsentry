package loader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"gopkg.in/yaml.v3"
)

// PodDocument holds a parsed Pod with its source metadata.
type PodDocument struct {
	Name      string
	Namespace string
	Spec      *corev1.PodSpec
	Source    string
}

type rawMeta struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
}

// ParsePods reads all Pod documents from a YAML byte slice, including
// multi-document YAML files separated by ---.
func ParsePods(data []byte, source string) ([]PodDocument, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var pods []PodDocument

	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decoding yaml from %s: %w", source, err)
		}

		if len(node.Content) == 0 {
			continue
		}

		jsonBytes, err := marshalNodeToJSON(&node)
		if err != nil {
			return nil, fmt.Errorf("converting yaml to json from %s: %w", source, err)
		}

		var meta rawMeta
		if err := json.Unmarshal(jsonBytes, &meta); err != nil {
			continue
		}

		if meta.Kind == "" || meta.Kind != "Pod" {
			continue
		}

		var podObj struct {
			Spec corev1.PodSpec `json:"spec"`
		}
		if err := json.Unmarshal(jsonBytes, &podObj); err != nil {
			return nil, fmt.Errorf("parsing pod spec from %s: %w", source, err)
		}

		ns := meta.Metadata.Namespace
		if ns == "" {
			ns = "default"
		}

		pods = append(pods, PodDocument{
			Name:      meta.Metadata.Name,
			Namespace: ns,
			Spec:      &podObj.Spec,
			Source:    source,
		})
	}

	return pods, nil
}

func marshalNodeToJSON(node *yaml.Node) ([]byte, error) {
	yamlBytes, err := yaml.Marshal(node)
	if err != nil {
		return nil, fmt.Errorf("marshaling yaml node: %w", err)
	}
	jsonBytes, err := sigsyaml.YAMLToJSON(yamlBytes)
	if err != nil {
		return nil, fmt.Errorf("converting to json: %w", err)
	}
	return jsonBytes, nil
}

// ensure sigsyaml is used (avoids import removal)
var _ = sigsyaml.YAMLToJSON
