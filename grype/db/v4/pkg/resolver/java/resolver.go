package java

import (
	"fmt"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/packageurl-go"
	"strings"
)

type Resolver struct {
}

func (r *Resolver) Type() resolver.Type {
	return resolver.Java
}

func (r *Resolver) Normalize(name string) string {
	return strings.ToLower(name)
}

func (r *Resolver) Resolve(p grypePkg.Package) []string {
	names := internal.NewStringSet()

	// The current default for the Java ecosystem is to use a Maven-like identifier of the form
	// "<group-name>:<artifact-name>"
	if metadata, ok := p.Metadata.(grypePkg.JavaMetadata); ok {
		if metadata.PomGroupID != "" {
			if metadata.PomArtifactID != "" {
				names.Add(r.Normalize(fmt.Sprintf("%s:%s", metadata.PomGroupID, metadata.PomArtifactID)))
			}
			if metadata.ManifestName != "" {
				names.Add(r.Normalize(fmt.Sprintf("%s:%s", metadata.PomGroupID, metadata.ManifestName)))
			}
		}
	}

	if p.PURL != "" {
		purl, err := packageurl.FromString(p.PURL)
		if err != nil {
			log.Warnf("unable to resolve java package identifier from purl=%q: %+v", p.PURL, err)
		} else {
			names.Add(r.Normalize(fmt.Sprintf("%s:%s", purl.Namespace, purl.Name)))
		}
	}

	return names.ToSlice()
}
