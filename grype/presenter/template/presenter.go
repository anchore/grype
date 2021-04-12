package template

import (
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"text/template"

	"github.com/anchore/grype/grype"

	"github.com/mitchellh/go-homedir"

	"github.com/anchore/grype/grype/presenter/models"
)

// The Name of the kind of presenter.
const Name = "template"

// Presenter is an implementation of presenter.Presenter that formats output according to a user-provided Go text template.
type Presenter struct {
	pathToTemplateFile string
}

// NewPresenter returns a new template.Presenter.
func NewPresenter(pathToTemplateFile string) *Presenter {
	return &Presenter{
		pathToTemplateFile: pathToTemplateFile,
	}
}

// Present creates output using a user-supplied Go template.
func (pres *Presenter) Present(output io.Writer, analysis grype.Analysis) error {
	expandedPathToTemplateFile, err := homedir.Expand(pres.pathToTemplateFile)
	if err != nil {
		return fmt.Errorf("unable to expand path %q", pres.pathToTemplateFile)
	}

	templateContents, err := ioutil.ReadFile(expandedPathToTemplateFile)
	if err != nil {
		return fmt.Errorf("unable to get output template: %w", err)
	}

	templateName := expandedPathToTemplateFile
	tmpl, err := template.New(templateName).Funcs(funcMap).Parse(string(templateContents))
	if err != nil {
		return fmt.Errorf("unable to parse template: %w", err)
	}

	document, err := models.NewDocument(analysis)
	if err != nil {
		return err
	}

	err = tmpl.Execute(output, document)
	if err != nil {
		return fmt.Errorf("unable to execute supplied template: %w", err)
	}

	return nil
}

// These are custom functions available to template authors.
var funcMap = template.FuncMap{
	"getLastIndex": func(collection interface{}) int {
		if v := reflect.ValueOf(collection); v.Kind() == reflect.Slice {
			return v.Len() - 1
		}

		return 0
	},
}
