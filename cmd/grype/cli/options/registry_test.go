package options

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/stereoscope/pkg/image"
)

func TestHasNonEmptyCredentials(t *testing.T) {
	tests := []struct {
		username, password, token, cert, key string
		expected                             bool
	}{

		{
			"", "", "", "", "",
			false,
		},
		{
			"user", "", "", "", "",
			false,
		},
		{
			"", "pass", "", "", "",
			false,
		},
		{
			"", "pass", "tok", "", "",
			true,
		},
		{
			"user", "", "tok", "", "",
			true,
		},
		{
			"", "", "tok", "", "",
			true,
		},
		{
			"user", "pass", "tok", "", "",
			true,
		},

		{
			"user", "pass", "", "", "",
			true,
		},
		{
			"", "", "", "cert", "key",
			true,
		},
		{
			"", "", "", "cert", "",
			false,
		},
		{
			"", "", "", "", "key",
			false,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			assert.Equal(t, test.expected, hasNonEmptyCredentials(test.username, test.password, test.token, test.cert, test.key))
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
		{
			name: "provide all tls configuration",
			input: registry{
				CACert:                "ca.crt",
				InsecureSkipTLSVerify: true,
				Auth: []RegistryCredentials{
					{
						TLSCert: "client.crt",
						TLSKey:  "client.key",
					},
				},
			},
			expected: image.RegistryOptions{
				CAFileOrDir:           "ca.crt",
				InsecureSkipTLSVerify: true,
				Credentials: []image.RegistryCredentials{
					{
						ClientCert: "client.crt",
						ClientKey:  "client.key",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, &test.expected, test.input.ToOptions())
		})
	}
}
