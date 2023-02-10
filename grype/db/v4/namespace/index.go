package namespace

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/db/v4/namespace/cpe"
	"github.com/anchore/grype/grype/db/v4/namespace/distro"
	"github.com/anchore/grype/grype/db/v4/namespace/language"
	grypeDistro "github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Index struct {
	all         []Namespace
	byLanguage  map[syftPkg.Language][]*language.Namespace
	byDistroKey map[string][]*distro.Namespace
	cpe         []*cpe.Namespace
}

func FromStrings(namespaces []string) (*Index, error) {
	all := make([]Namespace, 0)
	byLanguage := make(map[syftPkg.Language][]*language.Namespace)
	byDistroKey := make(map[string][]*distro.Namespace)
	cpeNamespaces := make([]*cpe.Namespace, 0)

	for _, n := range namespaces {
		ns, err := FromString(n)

		if err != nil {
			log.Warnf("unable to create namespace object from namespace=%s: %+v", n, err)
			continue
		}

		all = append(all, ns)

		switch nsObj := ns.(type) {
		case *language.Namespace:
			l := nsObj.Language()
			if _, ok := byLanguage[l]; !ok {
				byLanguage[l] = make([]*language.Namespace, 0)
			}

			byLanguage[l] = append(byLanguage[l], nsObj)
		case *distro.Namespace:
			distroKey := fmt.Sprintf("%s:%s", nsObj.DistroType(), nsObj.Version())
			if _, ok := byDistroKey[distroKey]; !ok {
				byDistroKey[distroKey] = make([]*distro.Namespace, 0)
			}

			byDistroKey[distroKey] = append(byDistroKey[distroKey], nsObj)
		case *cpe.Namespace:
			cpeNamespaces = append(cpeNamespaces, nsObj)
		default:
			log.Warnf("unable to index namespace=%s", n)
			continue
		}
	}

	return &Index{
		all:         all,
		byLanguage:  byLanguage,
		byDistroKey: byDistroKey,
		cpe:         cpeNamespaces,
	}, nil
}

func (i *Index) NamespacesForLanguage(l syftPkg.Language) []*language.Namespace {
	if _, ok := i.byLanguage[l]; ok {
		return i.byLanguage[l]
	}

	return nil
}

func (i *Index) NamespacesForDistro(d *grypeDistro.Distro) []*distro.Namespace {
	if d == nil {
		return nil
	}

	if d.IsRolling() {
		distroKey := fmt.Sprintf("%s:%s", strings.ToLower(d.Type.String()), "rolling")
		if v, ok := i.byDistroKey[distroKey]; ok {
			return v
		}
	}

	var versionSegments []int
	if d.Version != nil {
		versionSegments = d.Version.Segments()
	}

	if len(versionSegments) > 0 {
		// First attempt a direct match on distro full name and version
		distroKey := fmt.Sprintf("%s:%s", strings.ToLower(d.Type.String()), d.FullVersion())

		if v, ok := i.byDistroKey[distroKey]; ok {
			return v
		}

		if len(versionSegments) == 3 {
			// Try with only first two version components
			distroKey = fmt.Sprintf("%s:%d.%d", strings.ToLower(d.Type.String()), versionSegments[0], versionSegments[1])
			if v, ok := i.byDistroKey[distroKey]; ok {
				return v
			}

			// Try using only major version component
			distroKey = fmt.Sprintf("%s:%d", strings.ToLower(d.Type.String()), versionSegments[0])
			if v, ok := i.byDistroKey[distroKey]; ok {
				return v
			}
		}

		// Fall back into the manual mapping logic derived from
		// https://github.com/anchore/enterprise/blob/eb71bc6686b9f4c92347a4e95bec828cee879197/anchore_engine/services/policy_engine/__init__.py#L127-L140
		switch d.Type {
		case grypeDistro.CentOS, grypeDistro.RedHat, grypeDistro.Fedora, grypeDistro.RockyLinux, grypeDistro.AlmaLinux, grypeDistro.Gentoo:
			// TODO: there is no mapping of fedora version to RHEL latest version (only the name)
			distroKey = fmt.Sprintf("%s:%d", strings.ToLower(string(grypeDistro.RedHat)), versionSegments[0])
			if v, ok := i.byDistroKey[distroKey]; ok {
				return v
			}
		}
	}

	return nil
}

func (i *Index) CPENamespaces() []*cpe.Namespace {
	return i.cpe
}
