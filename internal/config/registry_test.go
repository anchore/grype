package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestRegistryOptions(t *testing.T) {
	tests := []struct {
		InsecureSkipTLSVerify bool
		InsecureUseHTTP       bool
	}{
		{
			false, false,
		},
		{
			true, false,
		},
		{
			false, true,
		},
		{
			true, true,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			reg := registry{}
			reg.InsecureSkipTLSVerify = test.InsecureSkipTLSVerify
			reg.InsecureUseHTTP = test.InsecureUseHTTP
			opt := reg.ToOptions()
			assert.Equal(t, opt.InsecureSkipTLSVerify, test.InsecureSkipTLSVerify)
			assert.Equal(t, opt.InsecureUseHTTP, test.InsecureUseHTTP)
		})
	}
}
