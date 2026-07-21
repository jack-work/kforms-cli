// Package form parses YAML form definitions into the API's JSON shape.
// Required defaults to true; only explicit `required: false` opts out —
// so the YAML stays terse for the common case of "everything mandatory".
package form

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/jack-work/kforms-cli/internal/api"
)

// yamlField mirrors the on-disk shape. Required is a *bool so we can
// distinguish absent (default true) from explicit false.
type yamlField struct {
	Name     string         `yaml:"name"`
	Label    string         `yaml:"label"`
	Kind     string         `yaml:"kind"`
	Required *bool          `yaml:"required,omitempty"`
	Config   map[string]any `yaml:"config,omitempty"`
}

// yamlMaterial mirrors one entry in the top-level `materials:` array.
// Exactly one of Path/SHA256 must be set. Label is optional.
type yamlMaterial struct {
	Path   string `yaml:"path,omitempty"`
	SHA256 string `yaml:"sha256,omitempty"`
	Label  string `yaml:"label,omitempty"`
}

type yamlForm struct {
	Slug        string         `yaml:"slug"`
	Title       string         `yaml:"title"`
	Description string         `yaml:"description,omitempty"`
	Materials   []yamlMaterial `yaml:"materials,omitempty"`
	Fields      []yamlField    `yaml:"fields"`
}

// MaterialSpec is a parsed entry from the YAML materials array. Exactly
// one of Path or SHA256 is non-empty (Validate enforces this).
type MaterialSpec struct {
	Path   string
	SHA256 string
	Label  string
}

// Doc is a parsed form YAML: the API-shaped form plus its materials
// sidecar. Materials are managed via a separate endpoint, so we keep
// them out of api.Form and hand them back alongside.
type Doc struct {
	Form      *api.Form
	Materials []MaterialSpec
	// BaseDir is the directory of the YAML file (or "" when parsed from
	// bytes). Callers use it to resolve relative material paths.
	BaseDir string
}

// LoadDoc reads and parses a form YAML file.
func LoadDoc(path string) (*Doc, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	d, err := ParseDoc(bs)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		d.BaseDir = filepath.Dir(abs)
	}
	return d, nil
}

// LoadYAML is a thin wrapper preserved for any callers that only want
// the form portion. Prefer LoadDoc.
func LoadYAML(path string) (*api.Form, error) {
	d, err := LoadDoc(path)
	if err != nil {
		return nil, err
	}
	return d.Form, nil
}

func ParseDoc(bs []byte) (*Doc, error) {
	var y yamlForm
	if err := yaml.Unmarshal(bs, &y); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if y.Slug == "" {
		return nil, fmt.Errorf("form yaml missing required field: slug")
	}
	if y.Title == "" {
		return nil, fmt.Errorf("form yaml missing required field: title")
	}
	f := &api.Form{
		Slug:        y.Slug,
		Title:       y.Title,
		Description: y.Description,
		Fields:      make([]api.Field, 0, len(y.Fields)),
	}
	for i, fld := range y.Fields {
		if fld.Name == "" {
			return nil, fmt.Errorf("field[%d] missing name", i)
		}
		if fld.Kind == "" {
			return nil, fmt.Errorf("field[%d] (%s) missing kind", i, fld.Name)
		}
		required := true
		if fld.Required != nil {
			required = *fld.Required
		}
		f.Fields = append(f.Fields, api.Field{
			Name:     fld.Name,
			Label:    fld.Label,
			Kind:     fld.Kind,
			Required: required,
			Config:   fld.Config,
		})
	}
	mats := make([]MaterialSpec, 0, len(y.Materials))
	for i, m := range y.Materials {
		hasPath := m.Path != ""
		hasSHA := m.SHA256 != ""
		if hasPath == hasSHA {
			return nil, fmt.Errorf("materials[%d]: exactly one of path or sha256 must be set", i)
		}
		mats = append(mats, MaterialSpec{
			Path:   m.Path,
			SHA256: m.SHA256,
			Label:  m.Label,
		})
	}
	return &Doc{Form: f, Materials: mats}, nil
}

// ParseYAML preserves the old surface for form-only callers.
func ParseYAML(bs []byte) (*api.Form, error) {
	d, err := ParseDoc(bs)
	if err != nil {
		return nil, err
	}
	return d.Form, nil
}

// ResolvedPath returns the absolute filesystem path for a material's
// Path field, resolved relative to the YAML file's directory. If Path
// is already absolute it is returned unchanged. Returns "" for
// sha-only entries.
func (m MaterialSpec) ResolvedPath(baseDir string) string {
	if m.Path == "" {
		return ""
	}
	if filepath.IsAbs(m.Path) {
		return m.Path
	}
	if baseDir == "" {
		return m.Path
	}
	return filepath.Join(baseDir, m.Path)
}

// DumpDoc serializes a form + materials back to YAML for the
// edit-in-$EDITOR flow.
func DumpDoc(d *Doc) ([]byte, error) {
	y := yamlForm{
		Slug:        d.Form.Slug,
		Title:       d.Form.Title,
		Description: d.Form.Description,
	}
	for _, m := range d.Materials {
		y.Materials = append(y.Materials, yamlMaterial{
			Path:   m.Path,
			SHA256: m.SHA256,
			Label:  m.Label,
		})
	}
	for _, fld := range d.Form.Fields {
		yf := yamlField{
			Name:   fld.Name,
			Label:  fld.Label,
			Kind:   fld.Kind,
			Config: fld.Config,
		}
		if !fld.Required {
			no := false
			yf.Required = &no
		}
		y.Fields = append(y.Fields, yf)
	}
	return yaml.Marshal(&y)
}

// DumpYAML preserves the old form-only surface.
func DumpYAML(f *api.Form) ([]byte, error) {
	return DumpDoc(&Doc{Form: f})
}
