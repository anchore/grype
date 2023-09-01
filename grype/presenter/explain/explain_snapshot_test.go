package explain_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/anchore/grype/grype/presenter/explain"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"
)

func TestExplainSnapshot(t *testing.T) {
	// load sample json
	// TODO: make and commit minimal sample JSON
	r, err := os.Open("./test-fixtures/keycloak-test.json")
	require.NoError(t, err)

	// parse to models.Document
	doc := models.Document{}
	decoder := json.NewDecoder(r)
	err = decoder.Decode(&doc)
	require.NoError(t, err)
	// create explain.VulnerabilityExplainer
	w := bytes.NewBufferString("")
	explainer := explain.NewVulnerabilityExplainer(w, &doc)
	// call ExplainByID
	err = explainer.ExplainByID([]string{"CVE-2020-12413"})
	require.NoError(t, err)
	// assert output
	snaps.MatchSnapshot(t, w.String())
}
