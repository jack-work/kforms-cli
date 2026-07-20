package form

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDocMaterials(t *testing.T) {
	yml := `slug: t
title: T
materials:
  - path: ./sub/thing.docx
    label: Thing
  - sha256: deadbeef
    label: Existing
fields:
  - name: x
    kind: short_text
`
	d, err := ParseDoc([]byte(yml))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	if len(d.Materials) != 2 {
		t.Fatalf("want 2 materials, got %d", len(d.Materials))
	}
	if d.Materials[0].Path != "./sub/thing.docx" || d.Materials[0].Label != "Thing" {
		t.Fatalf("materials[0] wrong: %+v", d.Materials[0])
	}
	if d.Materials[1].SHA256 != "deadbeef" {
		t.Fatalf("materials[1] wrong: %+v", d.Materials[1])
	}
}

func TestParseDocRejectsBothOrNeither(t *testing.T) {
	both := `slug: t
title: T
materials:
  - path: ./x
    sha256: abc
fields: []
`
	if _, err := ParseDoc([]byte(both)); err == nil {
		t.Fatal("expected error for both path+sha, got nil")
	}
	neither := `slug: t
title: T
materials:
  - label: naked
fields: []
`
	if _, err := ParseDoc([]byte(neither)); err == nil {
		t.Fatal("expected error for empty entry, got nil")
	}
}

func TestResolvedPathRelativeToYAMLDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sub, "thing.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(dir, "form.yaml")
	yml := `slug: t
title: T
materials:
  - path: ./sub/thing.txt
    label: Thing
fields:
  - name: x
    kind: short_text
`
	if err := os.WriteFile(yamlPath, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	// Change CWD elsewhere to prove resolution is relative to YAML dir,
	// not CWD.
	cwd, _ := os.Getwd()
	other := t.TempDir()
	if err := os.Chdir(other); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)

	d, err := LoadDoc(yamlPath)
	if err != nil {
		t.Fatalf("LoadDoc: %v", err)
	}
	resolved := d.Materials[0].ResolvedPath(d.BaseDir)
	if _, err := os.Stat(resolved); err != nil {
		t.Fatalf("resolved path %q not found: %v", resolved, err)
	}
	// Sanity: same content.
	bs, err := os.ReadFile(resolved)
	if err != nil || string(bs) != "x" {
		t.Fatalf("resolved wrong file: %v %q", err, string(bs))
	}
}

func TestResolvedPathAbsolute(t *testing.T) {
	m := MaterialSpec{Path: "/etc/hostname"}
	got := m.ResolvedPath("/nowhere")
	if got != "/etc/hostname" {
		t.Fatalf("absolute path should pass through, got %q", got)
	}
}
