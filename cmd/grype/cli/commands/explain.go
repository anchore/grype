package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/explain"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
)

type explainOptions struct {
	CVEIDs []string `yaml:"cve-ids" json:"cve-ids" mapstructure:"cve-ids"`
}

var _ clio.FlagAdder = (*explainOptions)(nil)

func (d *explainOptions) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&d.CVEIDs, "id", "", "CVE IDs to explain")
}

func Explain(app clio.Application) *cobra.Command {
	opts := &explainOptions{}

	cmd := &cobra.Command{
		Use:     "explain --id [VULNERABILITY ID]",
		Short:   "Ask grype to explain a set of findings",
		PreRunE: disableUI(app),
		RunE: func(_ *cobra.Command, _ []string) error {
			log.Warn("grype explain is a prototype feature and is subject to change")
			isStdinPipeOrRedirect, err := internal.IsStdinPipeOrRedirect()
			if err != nil {
				log.Warnf("unable to determine if there is piped input: %+v", err)
				isStdinPipeOrRedirect = false
			}
			if isStdinPipeOrRedirect {
				// TODO: eventually detect different types of input; for now assume grype json
				var parseResult models.Document
				decoder := json.NewDecoder(os.Stdin)
				err := decoder.Decode(&parseResult)
				if err != nil {
					return fmt.Errorf("unable to parse piped input: %+v", err)
				}
				explainer := explain.NewVulnerabilityExplainer(os.Stdout, &parseResult)
				return explainer.ExplainByID(opts.CVEIDs)
			}
			// perform a scan, then explain requested CVEs
			// TODO: implement
			return fmt.Errorf("requires grype json on stdin, please run 'grype -o json ... | grype explain ...'")
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Opts *explainOptions `json:"-" yaml:"-" mapstructure:"-"`
	}

	return app.SetupCommand(cmd, &configWrapper{opts})
}
