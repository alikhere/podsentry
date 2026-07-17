package loader

import (
	"testing"
)

var simplePodYAML = []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  namespace: production
spec:
  containers:
  - name: nginx
    image: nginx:latest
`)

var multiDocYAML = []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: first
spec:
  containers:
  - name: app
    image: app:latest
---
apiVersion: v1
kind: Pod
metadata:
  name: second
spec:
  containers:
  - name: sidecar
    image: sidecar:latest
`)

var mixedKindsYAML = []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  key: value
---
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: main
    image: main:latest
`)

func TestParsePodsSingle(t *testing.T) {
	pods, err := ParsePods(simplePodYAML, "test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(pods))
	}
	if pods[0].Name != "nginx" {
		t.Errorf("expected name 'nginx', got %q", pods[0].Name)
	}
	if pods[0].Namespace != "production" {
		t.Errorf("expected namespace 'production', got %q", pods[0].Namespace)
	}
}

func TestParsePodsMultiDocument(t *testing.T) {
	pods, err := ParsePods(multiDocYAML, "multi.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 2 {
		t.Fatalf("expected 2 pods, got %d", len(pods))
	}
}

func TestParsePodsMixedKinds(t *testing.T) {
	pods, err := ParsePods(mixedKindsYAML, "mixed.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("expected 1 pod (skipping ConfigMap), got %d", len(pods))
	}
	if pods[0].Name != "app" {
		t.Errorf("expected pod name 'app', got %q", pods[0].Name)
	}
}

func TestParsePodsDefaultNamespace(t *testing.T) {
	yaml := []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: no-ns
spec:
  containers:
  - name: app
    image: app:latest
`)
	pods, err := ParsePods(yaml, "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if pods[0].Namespace != "default" {
		t.Errorf("expected default namespace, got %q", pods[0].Namespace)
	}
}
