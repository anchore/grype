package pkg

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/source/sourceproviders"
)

func TestSourceProvidersIncludeContainersStorageBeforeRegistry(t *testing.T) {
	providers := sourceproviders.All("localhost/myimage:latest", nil)

	names := make([]string, 0, len(providers))
	for _, provider := range providers {
		names = append(names, provider.Value.Name())
	}

	storageIndex := slices.Index(names, "containers-storage")
	registryIndex := slices.Index(names, "oci-registry")
	require.NotEqual(t, -1, storageIndex)
	require.NotEqual(t, -1, registryIndex)
	require.Less(t, storageIndex, registryIndex)
	require.Contains(t, allSourceTags(), "containers-storage")
}
