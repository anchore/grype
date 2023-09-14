package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/syft/syft/source"
)

type Grype struct {
	Outputs                []string           `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, <presenter>=<file> the Presenter hint string to use for report formatting and the output file
	File                   string             `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	Distro                 string             `yaml:"distro" json:"distro" mapstructure:"distro"`                                           // --distro, specify a distro to explicitly use
	GenerateMissingCPEs    bool               `yaml:"add-cpes-if-none" json:"add-cpes-if-none" mapstructure:"add-cpes-if-none"`             // --add-cpes-if-none, automatically generate CPEs if they are not present in import (e.g. from a 3rd party SPDX document)
	OutputTemplateFile     string             `yaml:"output-template-file" json:"output-template-file" mapstructure:"output-template-file"` // -t, the template file to use for formatting the final report
	CheckForAppUpdate      bool               `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	OnlyFixed              bool               `yaml:"only-fixed" json:"only-fixed" mapstructure:"only-fixed"`                               // only fail if detected vulns have a fix
	OnlyNotFixed           bool               `yaml:"only-notfixed" json:"only-notfixed" mapstructure:"only-notfixed"`                      // only fail if detected vulns don't have a fix
	Platform               string             `yaml:"platform" json:"platform" mapstructure:"platform"`                                     // --platform, override the target platform for a container image
	Search                 search             `yaml:"search" json:"search" mapstructure:"search"`
	Ignore                 []match.IgnoreRule `yaml:"ignore" json:"ignore" mapstructure:"ignore"`
	Exclusions             []string           `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	DB                     Database           `yaml:"db" json:"db" mapstructure:"db"`
	ExternalSources        externalSources    `yaml:"external-sources" json:"externalSources" mapstructure:"external-sources"`
	Match                  matchConfig        `yaml:"match" json:"match" mapstructure:"match"`
	FailOn                 string             `yaml:"fail-on-severity" json:"fail-on-severity" mapstructure:"fail-on-severity"`
	Registry               registry           `yaml:"registry" json:"registry" mapstructure:"registry"`
	ShowSuppressed         bool               `yaml:"show-suppressed" json:"show-suppressed" mapstructure:"show-suppressed"`
	ByCVE                  bool               `yaml:"by-cve" json:"by-cve" mapstructure:"by-cve"` // --by-cve, indicates if the original match vulnerability IDs should be preserved or the CVE should be used instead
	Name                   string             `yaml:"name" json:"name" mapstructure:"name"`
	DefaultImagePullSource string             `yaml:"default-image-pull-source" json:"default-image-pull-source" mapstructure:"default-image-pull-source"`
	VexDocuments           []string           `yaml:"vex-documents" json:"vex-documents" mapstructure:"vex-documents"`
	VexAdd                 []string           `yaml:"vex-add" json:"vex-add" mapstructure:"vex-add"` // GRYPE_VEX_ADD
}

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*Grype)(nil)

func DefaultGrype(id clio.Identification) *Grype {
	return &Grype{
		Search:            defaultSearch(source.SquashedScope),
		DB:                DefaultDatabase(id),
		Match:             defaultMatchConfig(),
		ExternalSources:   defaultExternalSources(),
		CheckForAppUpdate: true,
		VexAdd:            []string{},
	}
}

// nolint:funlen
func (o *Grype) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Search.Scope,
		"scope", "s",
		fmt.Sprintf("selection of layers to analyze, options=%v", source.AllScopes),
	)

	flags.StringArrayVarP(&o.Outputs,
		"output", "o",
		fmt.Sprintf("report output formatter, formats=%v, deprecated formats=%v", format.AvailableFormats, format.DeprecatedFormats),
	)

	flags.StringVarP(&o.File,
		"file", "",
		"file to write the default report output to (default is STDOUT)",
	)

	flags.StringVarP(&o.Name,
		"name", "",
		"set the name of the target being analyzed",
	)

	flags.StringVarP(&o.Distro,
		"distro", "",
		"distro to match against in the format: <distro>:<version>",
	)

	flags.BoolVarP(&o.GenerateMissingCPEs,
		"add-cpes-if-none", "",
		"generate CPEs for packages with no CPE data",
	)

	flags.StringVarP(&o.OutputTemplateFile,
		"template", "t",
		"specify the path to a Go template file (requires 'template' output to be selected)")

	flags.StringVarP(&o.FailOn,
		"fail-on", "f",
		fmt.Sprintf("set the return code to 1 if a vulnerability is found with a severity >= the given severity, options=%v", vulnerability.AllSeverities()),
	)

	flags.BoolVarP(&o.OnlyFixed,
		"only-fixed", "",
		"ignore matches for vulnerabilities that are not fixed",
	)

	flags.BoolVarP(&o.OnlyNotFixed,
		"only-notfixed", "",
		"ignore matches for vulnerabilities that are fixed",
	)

	flags.BoolVarP(&o.ByCVE,
		"by-cve", "",
		"orient results by CVE instead of the original vulnerability ID when possible",
	)

	flags.BoolVarP(&o.ShowSuppressed,
		"show-suppressed", "",
		"show suppressed/ignored vulnerabilities in the output (only supported with table output format)",
	)

	flags.StringArrayVarP(&o.Exclusions,
		"exclude", "",
		"exclude paths from being scanned using a glob expression",
	)

	flags.StringVarP(&o.Platform,
		"platform", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')",
	)

	flags.StringArrayVarP(&o.VexDocuments,
		"vex", "",
		"a list of VEX documents to consider when producing scanning results",
	)
}

func (o *Grype) PostLoad() error {
	if o.FailOn != "" {
		failOnSeverity := *o.FailOnServerity()
		if failOnSeverity == vulnerability.UnknownSeverity {
			return fmt.Errorf("bad --fail-on severity value '%s'", o.FailOn)
		}
	}
	return nil
}

func (o Grype) FailOnServerity() *vulnerability.Severity {
	severity := vulnerability.ParseSeverity(o.FailOn)
	return &severity
}
