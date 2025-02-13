package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	legacyDistribution "github.com/anchore/grype/grype/db/v5/distribution"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/bus"
)

type dbProvidersOptions struct {
	Output                  string `yaml:"output" json:"output"`
	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbProvidersOptions)(nil)

func (d *dbProvidersOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[table, json])")
}

func DBProviders(app clio.Application) *cobra.Command {
	opts := &dbProvidersOptions{
		Output:          tableOutputFormat,
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List vulnerability providers that are in the database",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBProviders(opts, app)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden                   *dbProvidersOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBProviders(opts *dbProvidersOptions, app clio.Application) error {
	if opts.Experimental.DBv6 {
		return newDBProviders(opts)
	}
	return legacyDBProviders(opts, app)
}

func newDBProviders(opts *dbProvidersOptions) error {
	client, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}
	c, err := installation.NewCurator(opts.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	reader, err := c.Reader()
	if err != nil {
		return fmt.Errorf("unable to get providers: %w", err)
	}

	providerModels, err := reader.AllProviders()
	if err != nil {
		return fmt.Errorf("unable to get providers: %w", err)
	}

	sb := &strings.Builder{}

	switch opts.Output {
	case tableOutputFormat, textOutputFormat:
		displayDBProvidersTable(toProviders(providerModels), sb)
	case jsonOutputFormat:
		err = displayDBProvidersJSON(toProviders(providerModels), sb)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format: %s", opts.Output)
	}
	bus.Report(sb.String())

	return nil
}

type provider struct {
	Name         string     `json:"name"`
	Version      string     `json:"version"`
	Processor    string     `json:"processor"`
	DateCaptured *time.Time `json:"dateCaptured"`
	InputDigest  string     `json:"inputDigest"`
}

func toProviders(providers []v6.Provider) []provider {
	var res []provider
	for _, p := range providers {
		res = append(res, provider{
			Name:         p.ID,
			Version:      p.Version,
			Processor:    p.Processor,
			DateCaptured: p.DateCaptured,
			InputDigest:  p.InputDigest,
		})
	}
	return res
}

func displayDBProvidersTable(providers []provider, output io.Writer) {
	rows := [][]string{}
	for _, provider := range providers {
		rows = append(rows, []string{provider.Name, provider.Version, provider.Processor, provider.DateCaptured.String(), provider.InputDigest})
	}

	table := tablewriter.NewWriter(output)
	table.SetHeader([]string{"Name", "Version", "Processor", "Date Captured", "Input Digest"})

	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	table.AppendBulk(rows)
	table.Render()
}

func displayDBProvidersJSON(providers []provider, output io.Writer) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	err := encoder.Encode(providers)
	if err != nil {
		return fmt.Errorf("cannot display json: %w", err)
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// all legacy processing below ////////////////////////////////////////////////////////////////////////////////////////

type legacyProviderMetadata struct {
	Name              string `json:"name"`
	LastSuccessfulRun string `json:"lastSuccessfulRun"`
}

type dbProviders struct {
	Providers []legacyProviderMetadata `json:"providers"`
}

func legacyDBProviders(opts *dbProvidersOptions, app clio.Application) error {
	metadataFileLocation, err := getLegacyMetadataFileLocation(app)
	if err != nil {
		return nil
	}
	providers, err := getLegacyProviders(*metadataFileLocation)
	if err != nil {
		return err
	}

	sb := &strings.Builder{}

	switch opts.Output {
	case tableOutputFormat, textOutputFormat:
		displayLegacyProvidersTable(providers.Providers, sb)
	case jsonOutputFormat:
		err = displayLegacyProvidersJSON(providers, sb)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format: %s", opts.Output)
	}
	bus.Report(sb.String())

	return nil
}

func getLegacyMetadataFileLocation(app clio.Application) (*string, error) {
	dbCurator, err := legacyDistribution.NewCurator(options.DefaultDatabaseCommand(app.ID()).ToLegacyCuratorConfig())
	if err != nil {
		return nil, err
	}

	location := dbCurator.Status().Location

	return &location, nil
}

func getLegacyProviders(metadataFileLocation string) (*dbProviders, error) {
	metadataFile := path.Join(metadataFileLocation, "provider-metadata.json")

	file, err := os.Open(metadataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %w", err)
		}
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var providers dbProviders
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	err = json.Unmarshal(fileBytes, &providers)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal providers: %w", err)
	}

	return &providers, nil
}

func displayLegacyProvidersTable(providers []legacyProviderMetadata, output io.Writer) {
	rows := [][]string{}
	for _, provider := range providers {
		rows = append(rows, []string{provider.Name, provider.LastSuccessfulRun})
	}

	table := tablewriter.NewWriter(output)
	table.SetHeader([]string{"Name", "Last Successful Run"})

	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	table.AppendBulk(rows)
	table.Render()
}

func displayLegacyProvidersJSON(providers *dbProviders, output io.Writer) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	err := encoder.Encode(providers)
	if err != nil {
		return fmt.Errorf("cannot display json: %w", err)
	}
	return nil
}
