package store

import (
	"github.com/nextlinux/griffon/griffon/match"
	"github.com/nextlinux/griffon/griffon/vulnerability"
)

type Store struct {
	vulnerability.Provider
	vulnerability.MetadataProvider
	match.ExclusionProvider
}
