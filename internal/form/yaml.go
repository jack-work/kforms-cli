// Package form parses YAML form definitions into the API's JSON shape.
// Required defaults to true; only explicit `required: false` opts out —
// so the YAML stays terse for the common case of "everything mandatory".
package form

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/jack-work/gforms-cli/internal/api"
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

type yamlForm struct {
	Slug        string      `yaml:"slug"`
	Title       string      `yaml:"title"`
	Description string      `yaml:"description,omitempty"`
	Fields      []yamlField `yaml:"fields"`
}

// LoadYAML reads and parses a form YAML file.
func LoadYAML(path string) (*api.Form, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseYAML(bs)
}

func ParseYAML(bs []byte) (*api.Form, error) {
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
	out := &api.Form{
		Slug:        y.Slug,
		Title:       y.Title,
		Description: y.Description,
		Fields:      make([]api.Field, 0, len(y.Fields)),
	}
	for i, f := range y.Fields {
		if f.Name == "" {
			return nil, fmt.Errorf("field[%d] missing name", i)
		}
		if f.Kind == "" {
			return nil, fmt.Errorf("field[%d] (%s) missing kind", i, f.Name)
		}
		required := true
		if f.Required != nil {
			required = *f.Required
		}
		out.Fields = append(out.Fields, api.Field{
			Name:     f.Name,
			Label:    f.Label,
			Kind:     f.Kind,
			Required: required,
			Config:   f.Config,
		})
	}
	return out, nil
}

// DumpYAML serializes a Form back to YAML for the edit-in-$EDITOR flow.
// Required is emitted only when it's false — matches the input dialect.
func DumpYAML(f *api.Form) ([]byte, error) {
	y := yamlForm{
		Slug:        f.Slug,
		Title:       f.Title,
		Description: f.Description,
	}
	for _, fld := range f.Fields {
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
