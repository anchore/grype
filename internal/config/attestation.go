package config

type Attestation struct {
	Key              string `yaml:"key" json:"key" mapstructure:"key"`
	SkipVerification bool   `yaml:"skip-verification" json:"skip-verification" mapstructure:"skip-verification"`
}
