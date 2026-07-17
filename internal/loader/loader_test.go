package loader

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTmpYAML(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const podYAML = `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx:latest
`

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTmpYAML(t, dir, "pod.yaml", podYAML)

	pods, err := LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(pods))
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := LoadFile("/does/not/exist.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	writeTmpYAML(t, dir, "pod1.yaml", podYAML)
	writeTmpYAML(t, dir, "pod2.yml", podYAML)
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("text"), 0o644); err != nil {
		t.Fatal(err)
	}

	pods, err := LoadDir(dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 2 {
		t.Errorf("expected 2 pods, got %d", len(pods))
	}
}

func TestLoadDirRecursive(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTmpYAML(t, dir, "top.yaml", podYAML)
	writeTmpYAML(t, sub, "nested.yaml", podYAML)

	pods, err := LoadDir(dir, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 2 {
		t.Errorf("expected 2 pods (recursive), got %d", len(pods))
	}

	pods, err = LoadDir(dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 1 {
		t.Errorf("expected 1 pod (non-recursive), got %d", len(pods))
	}
}
