package provider

import (
	"context"
)

type Kind string

type Reader interface {
	ID() Identifier
	State() (*State, error)
}

type Writer interface {
	Update(context.Context) error
}

type Identifier struct {
	Name string `yaml:"name" json:"name" mapstructure:"name"`
	Kind Kind   `yaml:"kind,omitempty" json:"kind" mapstructure:"kind"`
}

type Providers []Reader

func (ps Providers) Filter(names ...string) Providers {
	var filtered Providers
	for _, p := range ps {
		for _, name := range names {
			if p.ID().Name == name {
				filtered = append(filtered, p)
			}
		}
	}
	return filtered
}

type Collection struct {
	Root      string
	Providers Providers
}
