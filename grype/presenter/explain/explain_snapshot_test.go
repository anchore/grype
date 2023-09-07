package explain_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/presenter/explain"
	"github.com/anchore/grype/grype/presenter/models"
)

func TestExplainSnapshot(t *testing.T) {
	// load sample json
	testCases := []struct {
		name             string
		fixture          string
		vulnerabilityIDs []string
	}{
		{
			name:             "keycloak-CVE-2020-12413",
			fixture:          "./test-fixtures/keycloak-test.json",
			vulnerabilityIDs: []string{"CVE-2020-12413"},
		},
		{
			name:             "chainguard-ruby-CVE-2023-28755",
			fixture:          "test-fixtures/chainguard-ruby-test.json",
			vulnerabilityIDs: []string{"CVE-2023-28755"},
		},
		{
			name: "test a GHSA",
			/*
				fixture created by:
				Saving output of
				grype anchore/test_images@sha256:10008791acbc5866de04108746a02a0c4029ce3a4400a9b3dad45d7f2245f9da -o json
				Then filtering matches to relevant ones:
				jq -c '.matches[]' | rg -e GHSA-cfh5-3ghh-wfjx -e CVE-2014-3577 | jq -s .
			*/
			fixture:          "test-fixtures/ghsa-test.json",
			vulnerabilityIDs: []string{"GHSA-cfh5-3ghh-wfjx"},
		},
		{
			name:             "test a CVE alias of a GHSA",
			fixture:          "test-fixtures/ghsa-test.json",
			vulnerabilityIDs: []string{"CVE-2014-3577"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := os.Open(tc.fixture)
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
			err = explainer.ExplainByID(tc.vulnerabilityIDs)
			require.NoError(t, err)
			// assert output
			snaps.MatchSnapshot(t, w.String())
		})
	}
}
