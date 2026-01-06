package provider

type redactable interface {
	Redact()
}

type Collection struct {
	Root      string
	Providers []Provider
}

type Config struct {
	Identifier `yaml:",inline" mapstructure:",squash"`
	Config     interface{} `yaml:"config,omitempty" json:"config" mapstructure:"config"`
}

func (c Config) Redact() {
	if c.Config == nil {
		return
	}
	if r, ok := c.Config.(redactable); ok {
		r.Redact()
	}
}

type Identifier struct {
	Name string `yaml:"name" json:"name" mapstructure:"name"`
	Kind Kind   `yaml:"kind,omitempty" json:"kind" mapstructure:"kind"`
}
