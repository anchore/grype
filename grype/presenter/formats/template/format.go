package template

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"text/template"

	"github.com/anchore/grype/grype/presenter/formats"

	models2 "github.com/anchore/grype/grype/presenter/formats/models"

	"github.com/anchore/grype/grype"

	"github.com/mitchellh/go-homedir"
)

// The Name of the Format.
const Name = "template"

// Format returns the "template" Format implementation.
func Format(pathToTemplateFile string) (formats.Format, error) {
	if pathToTemplateFile == "" {
		return nil, errors.New("must specify path to template file when using template format")
	}

	return func(analysis grype.Analysis, w io.Writer) error {
		return format(pathToTemplateFile, analysis, w)
	}, nil
}

func format(pathToTemplateFile string, analysis grype.Analysis, w io.Writer) error {
	expandedPathToTemplateFile, err := homedir.Expand(pathToTemplateFile)
	if err != nil {
		return fmt.Errorf("unable to expand path %q", pathToTemplateFile)
	}

	templateContents, err := ioutil.ReadFile(expandedPathToTemplateFile)
	if err != nil {
		return fmt.Errorf("unable to get w template: %w", err)
	}

	templateName := expandedPathToTemplateFile
	tmpl, err := template.New(templateName).Funcs(funcMap).Parse(string(templateContents))
	if err != nil {
		return fmt.Errorf("unable to parse template: %w", err)
	}

	document, err := models2.NewDocument(analysis)
	if err != nil {
		return err
	}

	err = tmpl.Execute(w, document)
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
