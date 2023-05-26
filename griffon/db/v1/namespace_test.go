package v1

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamespaceFromRecordSource(t *testing.T) {
	tests := []struct {
		Feed, Group string
		Namespace   string
	}{
		{
			Feed:      "vulnerabilities",
			Group:     "ubuntu:20.04",
			Namespace: "ubuntu:20.04",
		},
		{
			Feed:      "vulnerabilities",
			Group:     "alpine:3.9",
			Namespace: "alpine:3.9",
		},
		{
			Feed:      "vulnerabilities",
			Group:     "sles:12.5",
			Namespace: "sles:12.5",
		},
		{
			Feed:      "nvdv2",
			Group:     "nvdv2:cves",
			Namespace: "nvd",
		},
		{
			Feed:      "github",
			Group:     "github:python",
			Namespace: "github:python",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("feed=%q group=%q namespace=%q", test.Feed, test.Group, test.Namespace), func(t *testing.T) {
			actual, err := NamespaceForFeedGroup(test.Feed, test.Group)
			assert.NoError(t, err)
			assert.Equal(t, test.Namespace, actual)
		})
	}
}
