package namespace

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/grype/grype/db/v5/namespace/cpe"
	"github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
	grypeDistro "github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

var alpineVersionRegularExpression = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

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

//nolint:funlen,gocognit
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
		// Alpine is a special case since we can only match on x.y.z
		// after this things like x.y and x are valid namespace selections
		if d.Type == grypeDistro.Alpine {
			if v := getAlpineNamespace(i, d, versionSegments); v != nil {
				return v
			}
		}

		// Next attempt a direct match on distro full name and version
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
		case grypeDistro.Azure, grypeDistro.Mariner: // mariner was pre-release name for azure
			distroKey = fmt.Sprintf("%s:%s", strings.ToLower(string(grypeDistro.Mariner)), d.FullVersion())
			if v, ok := i.byDistroKey[distroKey]; ok {
				return v
			}
		}
	}

	// Fall back to alpine:edge if no version segments found
	// alpine:edge is labeled as alpine-x.x_alphaYYYYMMDD
	if versionSegments == nil && d.Type == grypeDistro.Alpine {
		distroKey := fmt.Sprintf("%s:%s", strings.ToLower(d.Type.String()), "edge")
		if v, ok := i.byDistroKey[distroKey]; ok {
			return v
		}
	}

	if versionSegments == nil && d.Type == grypeDistro.Debian && d.RawVersion == "unstable" {
		distroKey := fmt.Sprintf("%s:%s", strings.ToLower(d.Type.String()), "unstable")
		if v, ok := i.byDistroKey[distroKey]; ok {
			return v
		}
	}

	return nil
}

func getAlpineNamespace(i *Index, d *grypeDistro.Distro, versionSegments []int) []*distro.Namespace {
	// check if distro version matches x.y.z
	if alpineVersionRegularExpression.MatchString(d.RawVersion) {
		// Get the first two version components
		// TODO: should we update the namespaces in db generation to match x.y.z here?
		distroKey := fmt.Sprintf("%s:%d.%d", strings.ToLower(d.Type.String()), versionSegments[0], versionSegments[1])
		if v, ok := i.byDistroKey[distroKey]; ok {
			return v
		}
	}

	// If the version does not match x.y.z then it is edge
	// In this case it would have - or _ alpha,beta,etc
	// https://github.com/anchore/grype/issues/964#issuecomment-1290888755
	distroKey := fmt.Sprintf("%s:%s", strings.ToLower(d.Type.String()), "edge")
	if v, ok := i.byDistroKey[distroKey]; ok {
		return v
	}

	return nil
}

func (i *Index) CPENamespaces() []*cpe.Namespace {
	return i.cpe
}
