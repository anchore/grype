package config

import (
	"os"

	"github.com/anchore/stereoscope/pkg/image"
)

type RegistryCredentials struct {
	Authority string `yaml:"authority" json:"authority" mapstructure:"authority"`
	// IMPORTANT: do not show the username in any YAML/JSON output (sensitive information)
	Username string `yaml:"-" json:"-" mapstructure:"username"`
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password string `yaml:"-" json:"-" mapstructure:"password"`
	// IMPORTANT: do not show the token in any YAML/JSON output (sensitive information)
	Token string `yaml:"-" json:"-" mapstructure:"token"`
}

type registry struct {
	InsecureSkipTLSVerify bool                  `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool                  `yaml:"insecure-use-http" json:"insecure-use-http" mapstructure:"insecure-use-http"`
	Auth                  []RegistryCredentials `yaml:"auth" json:"auth" mapstructure:"auth"`
}

func (cfg *registry) parseConfigValues() {
	// there may be additional credentials provided by env var that should be appended to the set of credentials
	authority, username, password, token :=
		os.Getenv("GRYPE_REGISTRY_AUTH_AUTHORITY"),
		os.Getenv("GRYPE_REGISTRY_AUTH_USERNAME"),
		os.Getenv("GRYPE_REGISTRY_AUTH_PASSWORD"),
		os.Getenv("GRYPE_REGISTRY_AUTH_TOKEN")

	if hasNonEmptyCredentials(username, password, token) {
		// note: we prepend the credentials such that the environment variables take precedence over on-disk configuration.
		cfg.Auth = append([]RegistryCredentials{
			{
				Authority: authority,
				Username:  username,
				Password:  password,
				Token:     token,
			},
		}, cfg.Auth...)
	}
}

func hasNonEmptyCredentials(username, password, token string) bool {
	return password != "" && username != "" || token != ""
}

func (cfg *registry) ToOptions() *image.RegistryOptions {
	var auth = make([]image.RegistryCredentials, len(cfg.Auth))
	for i, a := range cfg.Auth {
		auth[i] = image.RegistryCredentials{
			Authority: a.Authority,
			Username:  a.Username,
			Password:  a.Password,
			Token:     a.Token,
		}
	}
	return &image.RegistryOptions{
		InsecureSkipTLSVerify: cfg.InsecureSkipTLSVerify,
		InsecureUseHTTP:       cfg.InsecureUseHTTP,
		Credentials:           auth,
	}
}
