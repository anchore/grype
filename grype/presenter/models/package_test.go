package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestNewPackageIncludesRustCargoLockSource(t *testing.T) {
	p := newPackage(pkg.New(syftPkg.Package{
		Metadata: syftPkg.RustCargoLockEntry{
			Name:    "workspace-package",
			Version: "0.1.0",
			Source:  "",
		},
	}))

	require.Equal(t, "RustMetadata", p.MetadataType)

	data, err := json.Marshal(p)
	require.NoError(t, err)
	require.JSONEq(t, `{"rustCargoLockSource":""}`, extractMetadataJSON(t, data))
}

func extractMetadataJSON(t *testing.T, data []byte) string {
	t.Helper()

	var document struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(data, &document))
	return string(document.Metadata)
}
