package provider

import (
	"context"
)

type Provider interface {
	Name() string
	Update(context.Context) error
	State() (*State, error)
}

type Providers []Provider

type Collection struct {
	Root      string
	Providers Providers
}

func (ps Providers) Filter(names ...string) Providers {
	var filtered Providers
	for _, p := range ps {
		for _, name := range names {
			if p.Name() == name {
				filtered = append(filtered, p)
			}
		}
	}
	return filtered
}
