package template

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
)

// Presenter is an implementation of presenter.Presenter that formats output according to a user-provided Go text template.
type Presenter struct {
	id                 clio.Identification
	document           models.Document
	pathToTemplateFile string
}

// NewPresenter returns a new template.Presenter.
func NewPresenter(pb models.PresenterConfig, templateFile string) *Presenter {
	return &Presenter{
		id:                 pb.ID,
		document:           pb.Document,
		pathToTemplateFile: templateFile,
	}
}

// Present creates output using a user-supplied Go template.
func (pres *Presenter) Present(output io.Writer) error {
	expandedPathToTemplateFile, err := homedir.Expand(pres.pathToTemplateFile)
	if err != nil {
		return fmt.Errorf("unable to expand path %q", pres.pathToTemplateFile)
	}

	templateContents, err := os.ReadFile(expandedPathToTemplateFile)
	if err != nil {
		return fmt.Errorf("unable to get output template: %w", err)
	}

	templateName := expandedPathToTemplateFile
	tmpl, err := template.New(templateName).Funcs(FuncMap).Parse(string(templateContents))
	if err != nil {
		return fmt.Errorf("unable to parse template: %w", err)
	}

	err = tmpl.Execute(output, pres.document)
	if err != nil {
		return fmt.Errorf("unable to execute supplied template: %w", err)
	}

	return nil
}

// FuncMap is a function that returns template.FuncMap with custom functions available to template authors.
var FuncMap = func() template.FuncMap {
	f := sprig.HermeticTxtFuncMap()
	f["getLastIndex"] = func(collection interface{}) int {
		if v := reflect.ValueOf(collection); v.Kind() == reflect.Slice {
			return v.Len() - 1
		}

		return 0
	}
	f["byMatchName"] = func(collection interface{}) interface{} {
		matches, ok := collection.([]models.Match)
		if !ok {
			return collection
		}

		models.SortMatches(matches, models.SortByPackage)
		return matches
	}
	return f
}()
