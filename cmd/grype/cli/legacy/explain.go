package legacy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	"github.com/spf13/cobra"
)

var vulnIDs []string

var explainCmd = &cobra.Command{
	Use:   "explain --id [VULNERABILITY ID]",
	Short: "Ask grype to explain a set of findings",
	RunE: func(cmd *cobra.Command, args []string) error {
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
			explainer := models.NewBetterVulnerabilityExplainer(os.Stdout, &parseResult)
			return explainer.ExplainByID(vulnIDs)
		}
		// perform a scan, then explain requested CVEs
		// TODO: implement
		return fmt.Errorf("not implemented")
	},
}

func init() {
	setExplainFlags(explainCmd)
}

func setExplainFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(&vulnIDs, "id", "", nil, "CVE ID to explain")
}
