package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/db/legacy/distribution"
	"github.com/anchore/grype/internal/bus"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

const metadataFileName = "provider-metadata.json"

type dbProviderMetadata struct {
	Name              string `json:"name"`
	LastSuccessfulRun string `json:"lastSuccessfulRun"`
}

type dbProviders struct {
	Providers []dbProviderMetadata `json:"providers"`
}

type dbProvidersOptions struct {
	Output string `yaml:"output" json:"output"`
}

var _ clio.FlagAdder = (*dbProvidersOptions)(nil)

func (d *dbProvidersOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[table, json])")
}

func DBProviders(app clio.Application) *cobra.Command {
	opts := &dbProvidersOptions{
		Output: "json",
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "providers",
		Short: "list vulnerability database providers",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBProviders(opts, app)
		},
	}, opts)
}

func runDBProviders(opts *dbProvidersOptions, app clio.Application) error {

	providers, err := getDBProviders(app)
	if err != nil {
		return err
	}

	sb := &strings.Builder{}

	switch opts.Output {
	case "table":
		displayDBProvidersTable(providers.Providers, sb)
	case "json":
		err = displayDBProvidersJSON(providers, sb)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format: %s", opts.Output)
	}
	bus.Report(sb.String())

	return nil
}

func getDBProviders(app clio.Application) (*dbProviders, error) {

	dbCurator, err := distribution.NewCurator(dbOptionsDefault(app.ID()).DB.ToCuratorConfig())
	if err != nil {
		return nil, err
	}

	metadataFileLocation := dbCurator.Status().Location
	metadataFile := path.Join(metadataFileLocation, metadataFileName)

	file, err := os.Open(metadataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %v", err)
		} else {
			return nil, fmt.Errorf("Error opening file: %v", err)
		}
	}
	defer file.Close()

	var providers dbProviders
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	err = json.Unmarshal(fileBytes, &providers)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal providers: %v", err)
	}

	return &providers, nil

}

func displayDBProvidersTable(providers []dbProviderMetadata, output io.Writer) {

	rows := [][]string{}
	for _, provider := range providers {
		rows = append(rows, []string{provider.Name, provider.LastSuccessfulRun})
	}

	table := tablewriter.NewWriter(output)
	table.SetHeader([]string{"Name", "Last Successful Run"})

	table.AppendBulk(rows)
	table.Render()

}

func displayDBProvidersJSON(providers *dbProviders, output io.Writer) error {

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	err := encoder.Encode(providers)
	if err != nil {
		return fmt.Errorf("cannot display json: %v", err)
	}
	return nil
}
