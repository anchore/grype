package legacy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/grype/grype/presenter/explain"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
)

var cveIDs []string

var explainCmd = &cobra.Command{
	Use:   "explain --id [VULNERABILITY ID]",
	Short: "Ask grype to explain a set of findings",
	RunE: func(cmd *cobra.Command, args []string) error {
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
			return explainer.ExplainByID(cveIDs)
		}
		// perform a scan, then explain requested CVEs
		// TODO: implement
		return fmt.Errorf("requires grype json on stdin, please run 'grype -o json ... | grype explain ...'")
	},
}

func init() {
	setExplainFlags(explainCmd)
}

func setExplainFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(&cveIDs, "id", "", nil, "CVE ID to explain")
}
