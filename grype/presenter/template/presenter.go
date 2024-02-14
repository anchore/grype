package template

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/mitchellh/go-homedir"
	"github.com/olekukonko/tablewriter"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

// Presenter is an implementation of presenter.Presenter that formats output according to a user-provided Go text template.
type Presenter struct {
	id                 clio.Identification
	matches            match.Matches
	ignoredMatches     []match.IgnoredMatch
	packages           []pkg.Package
	context            pkg.Context
	metadataProvider   vulnerability.MetadataProvider
	appConfig          interface{}
	dbStatus           interface{}
	pathToTemplateFile string
}

// NewPresenter returns a new template.Presenter.
func NewPresenter(pb models.PresenterConfig, templateFile string) *Presenter {
	return &Presenter{
		id:                 pb.ID,
		matches:            pb.Matches,
		ignoredMatches:     pb.IgnoredMatches,
		packages:           pb.Packages,
		metadataProvider:   pb.MetadataProvider,
		context:            pb.Context,
		appConfig:          pb.AppConfig,
		dbStatus:           pb.DBStatus,
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
	var tmpl *template.Template
	tmpl = template.New(templateName).Funcs(FuncMap(&tmpl))
	tmpl, err = tmpl.Parse(string(templateContents))
	if err != nil {
		return fmt.Errorf("unable to parse template: %w", err)
	}

	document, err := models.NewDocument(pres.id, pres.packages, pres.context, pres.matches, pres.ignoredMatches, pres.metadataProvider,
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
func FuncMap(tpl **template.Template) template.FuncMap {
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

		sort.Sort(models.MatchSort(matches))
		return matches
	}
	f["csvToTable"] = csvToTable(tpl)
	f["inline"] = inlineLines(tpl)
	f["uniqueLines"] = uniqueLines(tpl)
	return f
}

// csvToTable removes any whitespace-only lines, and renders a table based csv from the rendered template
func csvToTable(tpl **template.Template) func(templateName string, data any) (string, error) {
	return func(templateName string, data any) (string, error) {
		in, err := evalTemplate(tpl, templateName, data)
		if err != nil {
			return "", err
		}
		lines := strings.Split(in, "\n")

		// remove blank lines
		for i := 0; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if len(line) == 0 {
				lines = append(lines[:i], lines[i+1:]...)
				i--
				continue
			}
			lines[i] = line
		}

		header := strings.TrimSpace(lines[0])
		columns := strings.Split(header, ",")

		out := bytes.Buffer{}

		table := tablewriter.NewWriter(&out)
		table.SetHeader(columns)
		table.SetAutoWrapText(false)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)

		table.SetHeaderLine(false)
		table.SetBorder(false)
		table.SetAutoFormatHeaders(true)
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")
		table.SetRowSeparator("")
		table.SetTablePadding("  ")
		table.SetNoWhiteSpace(true)

		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			row := strings.Split(line, ",")
			for i := range row {
				row[i] = strings.TrimSpace(row[i])
			}
			table.Append(row)
		}

		table.Render()

		return out.String(), nil
	}
}

// inlineLines take a multi-line rendered template string and remove newlines
func inlineLines(tpl **template.Template) func(templateName string, data any) (string, error) {
	return func(templateName string, data any) (string, error) {
		text, err := evalTemplate(tpl, templateName, data)
		if err != nil {
			return "", err
		}
		text = regexp.MustCompile(`[\r\n]`).ReplaceAllString(text, "")
		return text, nil
	}
}

// uniqueLines remove any duplicate lines, leaving only one copy from a rendered template
func uniqueLines(tpl **template.Template) func(templateName string, data any) (string, error) {
	return func(templateName string, data any) (string, error) {
		text, err := evalTemplate(tpl, templateName, data)
		if err != nil {
			return "", err
		}
		allLines := strings.Split(text, "\n")
		out := bytes.Buffer{}
	nextLine:
		for i := 0; i < len(allLines); i++ {
			line := allLines[i]
			for j := 0; j < i; j++ {
				if allLines[j] == line {
					continue nextLine
				}
			}
			if out.Len() > 0 {
				out.WriteRune('\n')
			}
			out.WriteString(line)
		}
		if strings.HasSuffix(text, "\n") {
			out.WriteRune('\n')
		}
		return out.String(), nil
	}
}

func evalTemplate(tpl **template.Template, templateName string, data any) (string, error) {
	out := bytes.Buffer{}
	err := (*tpl).ExecuteTemplate(&out, templateName, data)
	if err != nil {
		return "", err
	}
	return out.String(), nil
}
