package template

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
)

// Presenter is an implementation of presenter.Presenter that processes a vulnerability
// scan report through a user-provided text/template. The default template data model is the
// JSON output shape (as produced by the JSON presenter), decoded into generic values
// (map[string]any, []any, string, etc.). The legacy Go struct document can be used instead
// by setting Legacy to true.
type Presenter struct {
	id                 clio.Identification
	document           models.Document
	pathToTemplateFile string
	legacy             bool
}

// NewPresenter returns a new template presenter that processes the given template file.
// When legacy is false, templates are executed against the JSON output shape of the report;
// when true, templates are executed against the Go struct document model (the historical behavior).
func NewPresenter(pb models.PresenterConfig, templateFile string, legacy bool) *Presenter {
	return &Presenter{
		id:                 pb.ID,
		document:           pb.Document,
		pathToTemplateFile: templateFile,
		legacy:             legacy,
	}
}

// Present creates a Report using a user-supplied template.
func (pres *Presenter) Present(output io.Writer) error {
	templateContents, err := pres.getTemplateContents()
	if err != nil {
		return err
	}

	templateName := pres.pathToTemplateFile
	funcMap := FuncMap()
	tmpl, err := template.New(templateName).Funcs(funcMap).Parse(templateContents)
	if err != nil {
		return fmt.Errorf("unable to parse template: %w", err)
	}

	doc, err := pres.templateData()
	if err != nil {
		return err
	}

	if err := tmpl.Execute(output, doc); err != nil {
		return fmt.Errorf("unable to execute supplied template: %w", err)
	}

	return nil
}

// templateData returns the data model templates are executed against: the JSON output shape
// by default, or the Go struct document when the legacy mode is enabled.
func (pres *Presenter) templateData() (any, error) {
	if pres.legacy {
		return pres.document, nil
	}

	// the JSON presenter marshals the same document; round-tripping through JSON gives
	// templates exactly the JSON output shape (field names and values)
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(pres.document); err != nil {
		return nil, fmt.Errorf("unable to encode document as JSON: %w", err)
	}

	var jsonDocument map[string]any
	if err := json.Unmarshal(buf.Bytes(), &jsonDocument); err != nil {
		return nil, fmt.Errorf("unable to decode JSON document for template: %w", err)
	}

	return jsonDocument, nil
}

// getTemplateContents reads and returns the contents of the template file
func (pres *Presenter) getTemplateContents() (string, error) {
	expandedPathToTemplateFile, err := homedir.Expand(pres.pathToTemplateFile)
	if err != nil {
		return "", fmt.Errorf("unable to expand path on template file: %w", err)
	}
	templateContents, err := os.ReadFile(expandedPathToTemplateFile)
	if err != nil {
		return "", fmt.Errorf("unable to get template contents: %w", err)
	}
	return string(templateContents), nil
}

// FuncMap is a function that returns a function map containing both
// custom and sprig functions.
func FuncMap() template.FuncMap {
	// Derived from the Helm function map (see https://github.com/helm/helm/blob/f98bcde7f80e62b02ba0f1b0c2ae60260ab2a840/pkg/engine/funcs.go)
	// HermeticTxtFuncMap returns a TextFuncMap without functions that leak information about the host (e.g. env, date, etc)
	f := sprig.HermeticTxtFuncMap()

	// add some extra functionality
	extra := template.FuncMap{
		"getLastIndex": func(collection any) any {
			if arr, ok := collection.([]interface{}); ok {
				return len(arr) - 1
			}
			return -1
		},
		"byMatchName": func(collection any) any {
			switch matches := collection.(type) {
			case []models.Match:
				models.SortMatches(matches, models.SortByPackage)
				return matches
			case []any:
				sort.SliceStable(matches, func(i, j int) bool {
					return jsonMatchSortKey(matches[i]) < jsonMatchSortKey(matches[j])
				})
				return matches
			default:
				return collection
			}
		},
	}

	for k, v := range extra {
		f[k] = v
	}

	return f
}

// jsonMatchSortKey extracts the sort key from a match in the JSON output shape,
// mirroring the package name + version ordering used for []models.Match.
func jsonMatchSortKey(match any) string {
	matchMap, ok := match.(map[string]any)
	if !ok {
		return ""
	}
	artifact, ok := matchMap["artifact"].(map[string]any)
	if !ok {
		return ""
	}
	name, _ := artifact["name"].(string)
	version, _ := artifact["version"].(string)
	return name + "@" + version
}
