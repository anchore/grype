package csaf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

const groupDoc = `{
  "document": {"category": "csaf_vex", "csaf_version": "2.0"},
  "product_tree": {
    "product_groups": [
      {"group_id": "CSAFGID-1", "product_ids": ["SPB-00260", "SPB-00261"]}
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2023-3817",
      "flags": [{"label": "vulnerable_code_not_present", "group_ids": ["CSAFGID-1"]}],
      "threats": [{"category": "impact", "details": "not exploitable", "product_ids": ["SPB-00261"], "group_ids": ["CSAFGID-1"]}]
    }
  ]
}`

func writeDoc(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "doc.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func resolveAndDecode(t *testing.T, path string) (map[string]any, bool) {
	t.Helper()
	raw, changed, err := resolveProductGroups(path)
	require.NoError(t, err)

	if !changed {
		return nil, false
	}

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	return doc, true
}

func Test_resolveProductGroups(t *testing.T) {
	t.Run("resolves group references into member product IDs", func(t *testing.T) {
		doc, changed := resolveAndDecode(t, writeDoc(t, groupDoc))
		require.True(t, changed)

		tree := doc["product_tree"].(map[string]any)
		assert.NotContains(t, tree, "product_groups", "the loader cannot parse group definitions, they must be removed")

		vuln := doc["vulnerabilities"].([]any)[0].(map[string]any)

		flag := vuln["flags"].([]any)[0].(map[string]any)
		assert.NotContains(t, flag, "group_ids")
		assert.Equal(t, []any{"SPB-00260", "SPB-00261"}, flag["product_ids"])

		// existing product IDs are kept when merging the group members
		threat := vuln["threats"].([]any)[0].(map[string]any)
		assert.NotContains(t, threat, "group_ids")
		assert.Equal(t, []any{"SPB-00261", "SPB-00260"}, threat["product_ids"])
	})

	t.Run("leaves documents without group fields untouched", func(t *testing.T) {
		doc := `{"document": {"category": "csaf_vex", "csaf_version": "2.0"}}`

		raw, changed, err := resolveProductGroups(writeDoc(t, doc))
		require.NoError(t, err)
		assert.False(t, changed)
		assert.Nil(t, raw)
	})

	t.Run("drops references to groups that are not defined", func(t *testing.T) {
		doc := `{
		  "document": {"category": "csaf_vex", "csaf_version": "2.0"},
		  "vulnerabilities": [
		    {"cve": "CVE-2023-3817", "flags": [{"label": "vulnerable_code_not_present", "group_ids": ["UNDEFINED"]}]}
		  ]
		}`

		resolved, changed := resolveAndDecode(t, writeDoc(t, doc))
		require.True(t, changed)

		flag := resolved["vulnerabilities"].([]any)[0].(map[string]any)["flags"].([]any)[0].(map[string]any)
		assert.NotContains(t, flag, "group_ids")
		assert.NotContains(t, flag, "product_ids", "no members could be resolved, nothing to assert")
	})

	t.Run("reports unreadable documents", func(t *testing.T) {
		_, _, err := resolveProductGroups(writeDoc(t, "not json"))
		assert.Error(t, err)
	})
}

func Test_loadAdvisory(t *testing.T) {
	t.Run("loads a document that only references products through groups", func(t *testing.T) {
		adv, err := loadAdvisory(filepath.Join("..", "testdata", "vex-docs", "csaf-product-groups.json"))
		require.NoError(t, err)
		require.NotNil(t, adv)

		vuln := adv.Vulnerabilities[0]
		require.NotNil(t, vuln.Flags)
		require.NotNil(t, vuln.Flags[0].ProductIds)
		assert.Equal(t, gocsaf.ProductID("SPB-00260"), *(*vuln.Flags[0].ProductIds)[0])
	})

	t.Run("returns the loader error for documents it cannot rescue", func(t *testing.T) {
		_, err := loadAdvisory(filepath.Join("..", "testdata", "vex-docs", "csaf-unparseable.json"))
		assert.Error(t, err)
	})
}

func Test_LooksLikeCSAF(t *testing.T) {
	t.Run("csaf documents", func(t *testing.T) {
		assert.True(t, LooksLikeCSAF(filepath.Join("..", "testdata", "vex-docs", "csaf-demo1.json")))
	})

	t.Run("csaf schema reference", func(t *testing.T) {
		doc := `{"$schema": "https://docs.oasis-open.org/csaf/ns/csaf-cvrf/v2.0/csaf_json_schema.json"}`
		assert.True(t, LooksLikeCSAF(writeDoc(t, doc)))
	})

	t.Run("other documents", func(t *testing.T) {
		assert.False(t, LooksLikeCSAF(filepath.Join("..", "testdata", "vex-docs", "openvex-demo1.json")))
	})

	t.Run("missing files", func(t *testing.T) {
		assert.False(t, LooksLikeCSAF(filepath.Join(t.TempDir(), "does-not-exist.json")))
	})
}
