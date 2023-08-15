package options

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/stereoscope/pkg/image"
)

func TestHasNonEmptyCredentials(t *testing.T) {
	tests := []struct {
		username, password, token string
		expected                  bool
	}{
		{
			"", "", "",
			false,
		},
		{
			"user", "", "",
			false,
		},
		{
			"", "pass", "",
			false,
		},
		{
			"", "pass", "tok",
			true,
		},
		{
			"user", "", "tok",
			true,
		},
		{
			"", "", "tok",
			true,
		},
		{
			"user", "pass", "tok",
			true,
		},

		{
			"user", "pass", "",
			true,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			assert.Equal(t, test.expected, hasNonEmptyCredentials(test.username, test.password, test.token))
		})
	}
}

func Test_registry_ToOptions(t *testing.T) {
	tests := []struct {
		name     string
		input    registry
		expected image.RegistryOptions
	}{
		{
			name:  "no registry options",
			input: registry{},
			expected: image.RegistryOptions{
				Credentials: []image.RegistryCredentials{},
			},
		},
		{
			name: "set InsecureSkipTLSVerify",
			input: registry{
				InsecureSkipTLSVerify: true,
			},
			expected: image.RegistryOptions{
				InsecureSkipTLSVerify: true,
				Credentials:           []image.RegistryCredentials{},
			},
		},
		{
			name: "set InsecureUseHTTP",
			input: registry{
				InsecureUseHTTP: true,
			},
			expected: image.RegistryOptions{
				InsecureUseHTTP: true,
				Credentials:     []image.RegistryCredentials{},
			},
		},
		{
			name: "set all bool options",
			input: registry{
				InsecureSkipTLSVerify: true,
				InsecureUseHTTP:       true,
			},
			expected: image.RegistryOptions{
				InsecureSkipTLSVerify: true,
				InsecureUseHTTP:       true,
				Credentials:           []image.RegistryCredentials{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, &test.expected, test.input.ToOptions())
		})
	}
}
