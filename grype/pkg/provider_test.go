package pkg

import (
	"io/ioutil"
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

type providerTestConfig struct {
	userInput   string
	scopeOpt    source.Scope
	readerBytes []byte
}

func TestDetermineProviderConfig(t *testing.T) {
	cases := []struct {
		name      string
		userInput string
		scopeOpt  source.Scope
		stdin     []byte
		expected  providerTestConfig
	}{
		{
			"explicit sbom path",
			"sbom:/Users/bob/sbom.json",
			source.SquashedScope,
			nil,
			providerTestConfig{
				"sbom:/Users/bob/sbom.json",
				source.SquashedScope,
				nil,
			},
		},
		{
			"explicit stdin",
			"",
			source.SquashedScope,
			[]byte("{some json}"),
			providerTestConfig{
				"",
				source.SquashedScope,
				[]byte("{some json}"),
			},
		},
		{
			"stdin and userInput",
			"some-value",
			source.SquashedScope,
			[]byte("{some json}"),
			providerTestConfig{
				"some-value",
				source.SquashedScope,
				[]byte("{some json}"),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawConfig := determineProviderConfig(tc.userInput, tc.scopeOpt, tc.stdin)

			actual := mapToProviderTestConfig(t, rawConfig)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func mapToProviderTestConfig(t *testing.T, rawConfig providerConfig) providerTestConfig {
	t.Helper()

	var readerBytes []byte

	if rawConfig.reader != nil {
		readerBytes, _ = ioutil.ReadAll(rawConfig.reader)
	}

	return providerTestConfig{
		rawConfig.userInput,
		rawConfig.scopeOpt,
		readerBytes,
	}
}
