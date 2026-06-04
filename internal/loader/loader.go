package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadFile reads a single YAML file and returns all Pod documents found in it.
func LoadFile(path string) ([]PodDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	return ParsePods(data, path)
}

// LoadDir walks a directory and loads Pod documents from all YAML files found.
// When recursive is false, only the top-level directory is scanned.
func LoadDir(dir string, recursive bool) ([]PodDocument, error) {
	var all []PodDocument

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("accessing path %s: %w", path, err)
		}
		if info.IsDir() {
			if !recursive && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if !isYAMLFile(path) {
			return nil
		}
		pods, err := LoadFile(path)
		if err != nil {
			return err
		}
		all = append(all, pods...)
		return nil
	}

	if err := filepath.Walk(dir, walkFn); err != nil {
		return nil, fmt.Errorf("walking directory %s: %w", dir, err)
	}

	return all, nil
}

// Load accepts either a file path or a directory path and returns all Pod
// documents found. When path is a directory and recursive is true, subdirectories
// are scanned as well.
func Load(path string, recursive bool) ([]PodDocument, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return LoadDir(path, recursive)
	}
	return LoadFile(path)
}

func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
