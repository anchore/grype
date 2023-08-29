package config

import (
	"os"

	"github.com/spf13/viper"

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

	TLSCert string `yaml:"tls-cert,omitempty" json:"tls-cert,omitempty" mapstructure:"tls-cert"`
	TLSKey  string `yaml:"tls-key,omitempty" json:"tls-key,omitempty" mapstructure:"tls-key"`
}

type registry struct {
	InsecureSkipTLSVerify bool                  `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool                  `yaml:"insecure-use-http" json:"insecure-use-http" mapstructure:"insecure-use-http"`
	Auth                  []RegistryCredentials `yaml:"auth" json:"auth" mapstructure:"auth"`
	CACert                string                `yaml:"ca-cert" json:"ca-cert" mapstructure:"ca-cert"`
}

func (cfg registry) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("registry.insecure-skip-tls-verify", false)
	v.SetDefault("registry.insecure-use-http", false)
	v.SetDefault("registry.auth", []RegistryCredentials{})
	v.SetDefault("registry.ca-cert", "")
}

//nolint:unparam
func (cfg *registry) parseConfigValues() error {
	// there may be additional credentials provided by env var that should be appended to the set of credentials
	authority, username, password, token, tlsCert, tlsKey :=
		os.Getenv("GRYPE_REGISTRY_AUTH_AUTHORITY"),
		os.Getenv("GRYPE_REGISTRY_AUTH_USERNAME"),
		os.Getenv("GRYPE_REGISTRY_AUTH_PASSWORD"),
		os.Getenv("GRYPE_REGISTRY_AUTH_TOKEN"),
		os.Getenv("GRYPE_REGISTRY_AUTH_TLS_CERT"),
		os.Getenv("GRYPE_REGISTRY_AUTH_TLS_KEY")

	if hasNonEmptyCredentials(username, password, token, tlsCert, tlsKey) {
		// note: we prepend the credentials such that the environment variables take precedence over on-disk configuration.
		cfg.Auth = append([]RegistryCredentials{
			{
				Authority: authority,
				Username:  username,
				Password:  password,
				Token:     token,
				TLSCert:   tlsCert,
				TLSKey:    tlsKey,
			},
		}, cfg.Auth...)
	}
	return nil
}

func hasNonEmptyCredentials(username, password, token, tlsCert, tlsKey string) bool {
	hasUserPass := username != "" && password != ""
	hasToken := token != ""
	hasTLSMaterial := tlsCert != "" && tlsKey != ""
	return hasUserPass || hasToken || hasTLSMaterial
}

func (cfg *registry) ToOptions() *image.RegistryOptions {
	var auth = make([]image.RegistryCredentials, len(cfg.Auth))
	for i, a := range cfg.Auth {
		auth[i] = image.RegistryCredentials{
			Authority:  a.Authority,
			Username:   a.Username,
			Password:   a.Password,
			Token:      a.Token,
			ClientCert: a.TLSCert,
			ClientKey:  a.TLSKey,
		}
	}

	return &image.RegistryOptions{
		InsecureSkipTLSVerify: cfg.InsecureSkipTLSVerify,
		InsecureUseHTTP:       cfg.InsecureUseHTTP,
		Credentials:           auth,
		CAFileOrDir:           cfg.CACert,
	}
}
