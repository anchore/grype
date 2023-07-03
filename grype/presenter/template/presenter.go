package template

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
)

// Presenter is an implementation of presenter.Presenter that formats output according to a user-provided Go text template.
type Presenter struct {
	matches            match.Matches
	ignoredMatches     []match.IgnoredMatch
	packages           []pkg.Package
	context            pkg.Context
	metadataProvider   vulnerability.MetadataProvider
	appConfig          interface{}
	dbStatus           interface{}
	outputFilePath     string
	pathToTemplateFile string
	fs                 afero.Fs
}

// NewPresenter returns a new template.Presenter.
func NewPresenter(fs afero.Fs, pb models.PresenterConfig, outputFilePath string, templateFile string) *Presenter {
	return &Presenter{
		matches:            pb.Matches,
		ignoredMatches:     pb.IgnoredMatches,
		packages:           pb.Packages,
		metadataProvider:   pb.MetadataProvider,
		context:            pb.Context,
		appConfig:          pb.AppConfig,
		dbStatus:           pb.DBStatus,
		outputFilePath:     outputFilePath,
		pathToTemplateFile: templateFile,
		fs:                 fs,
	}
}

// Present creates output using a user-supplied Go template.
func (pres *Presenter) Present(defaultOutput io.Writer) error {
	output, closer, err := file.GetWriter(pres.fs, defaultOutput, pres.outputFilePath)
	defer func() {
		if closer != nil {
			err := closer()
			if err != nil {
				log.Warnf("unable to write to report destination: %+v", err)
			}
		}
	}()
	if err != nil {
		return err
	}
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

	document, err := models.NewDocument(pres.packages, pres.context, pres.matches, pres.ignoredMatches, pres.metadataProvider,
		pres.appConfig, pres.dbStatus)
	if err != nil {
		return err
	}

	err = tmpl.Execute(output, document)
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

		sort.Sort(models.ByName(matches))
		return matches
	}
	return f
}()
