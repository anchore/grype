package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/bus"
)

type dbProvidersOptions struct {
	Output    string `yaml:"output" json:"output"`
	DBOptions `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbProvidersOptions)(nil)

func (d *dbProvidersOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[table, json])")
}

func DBProviders(app clio.Application) *cobra.Command {
	opts := &dbProvidersOptions{
		Output:    tableOutputFormat,
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List vulnerability providers that are in the database",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBProviders(opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden     *dbProvidersOptions `json:"-" yaml:"-" mapstructure:"-"`
		*DBOptions `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DBOptions: &opts.DBOptions})
}

func runDBProviders(opts *dbProvidersOptions) error {
	client, err := distribution.NewClient(opts.DB.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}
	c, err := installation.NewCurator(opts.DB.ToCuratorConfig(), client)
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
