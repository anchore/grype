package provider

import "context"

type Kind string

const (
	InternalKind Kind = "internal" // reserved, not implemented (golang vulnerability data providers in-repo)
	ExternalKind Kind = "external"
	VunnelKind   Kind = "vunnel" // special case of external
)

type Provider interface {
	ID() Identifier
	Update(context.Context) error
	State() (*State, error)
}

type Providers []Provider

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
