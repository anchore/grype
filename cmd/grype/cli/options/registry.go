package options

import (
	"os"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/image"
)

type RegistryCredentials struct {
	Authority string `yaml:"authority" json:"authority" mapstructure:"authority"`
	// IMPORTANT: do not show the username, password, or token in any output (sensitive information)
	Username secret `yaml:"username" json:"username" mapstructure:"username"`
	Password secret `yaml:"password" json:"password" mapstructure:"password"`
	Token    secret `yaml:"token" json:"token" mapstructure:"token"`

	TLSCert string `yaml:"tls-cert,omitempty" json:"tls-cert,omitempty" mapstructure:"tls-cert"`
	TLSKey  string `yaml:"tls-key,omitempty" json:"tls-key,omitempty" mapstructure:"tls-key"`
}

type registry struct {
	InsecureSkipTLSVerify bool                  `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool                  `yaml:"insecure-use-http" json:"insecure-use-http" mapstructure:"insecure-use-http"`
	Auth                  []RegistryCredentials `yaml:"auth" json:"auth" mapstructure:"auth"`
	CACert                string                `yaml:"ca-cert" json:"ca-cert" mapstructure:"ca-cert"`
}

var _ clio.PostLoader = (*registry)(nil)

func (cfg *registry) PostLoad() error {
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
				Username:  secret(username),
				Password:  secret(password),
				Token:     secret(token),
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
			Username:   a.Username.String(),
			Password:   a.Password.String(),
			Token:      a.Token.String(),
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
