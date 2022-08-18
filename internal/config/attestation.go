package config

type Attestation struct {
	PublicKey        string `yaml:"public-key" json:"public-key" mapstructure:"public-key"`
	SkipVerification bool   `yaml:"skip-verification" json:"skip-verification" mapstructure:"skip-verification"`
}
