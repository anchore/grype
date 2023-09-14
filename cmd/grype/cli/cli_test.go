package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
)

func Test_Command(t *testing.T) {
	root := Command(clio.Identification{
		Name:    "test-name",
		Version: "test-version",
	})

	require.Equal(t, root.Name(), "test-name")
	require.NotEmpty(t, root.Commands())
}
