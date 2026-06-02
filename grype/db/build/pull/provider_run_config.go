package pull

import (
	"github.com/anchore/grype/grype/db/provider"
)

// Redactable is implemented by provider configs whose contents should have any
// sensitive values registered with the application redaction store before logging.
type Redactable interface {
	Redact()
}

type ProviderRunConfig struct {
	provider.Identifier `yaml:",inline" mapstructure:",squash"`
	Config              any `yaml:"config,omitempty" json:"config" mapstructure:"config"`
}

func (c ProviderRunConfig) Redact() {
	if c.Config == nil {
		return
	}
	if r, ok := c.Config.(Redactable); ok {
		r.Redact()
	}
}
