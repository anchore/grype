package nvd

import (
	"fmt"
	"strings"

	"github.com/umisama/go-cpe"

	"github.com/anchore/grype/grype/db/internal/versionutil"
	"github.com/anchore/grype/grype/db/provider/unmarshal/nvd"
	"github.com/anchore/grype/internal/log"
)

const (
	ANY = "*"
	NA  = "-"
)

type pkgCandidate struct {
	Product        string
	Vendor         string
	TargetSoftware string
	PlatformCPE    string
}

func (p pkgCandidate) String() string {
	if p.PlatformCPE == "" {
		return fmt.Sprintf("%s|%s|%s", p.Vendor, p.Product, p.TargetSoftware)
	}

	return fmt.Sprintf("%s|%s|%s|%s", p.Vendor, p.Product, p.TargetSoftware, p.PlatformCPE)
}

func newPkgCandidate(tCfg Config, match nvd.CpeMatch, platformCPE string) (*pkgCandidate, error) {
	// we are only interested in packages that are vulnerable (not related to secondary match conditioning)
	if !match.Vulnerable {
		return nil, nil
	}

	c, err := cpe.NewItemFromFormattedString(match.Criteria)
	if err != nil {
		return nil, fmt.Errorf("unable to create uniquePkgEntry from '%s': %w", match.Criteria, err)
	}

	// we are interested in applications, conditionally operating systems, but never hardware
	part := c.Part()
	if !tCfg.CPEParts.Has(string(part)) {
		return nil, nil
	}

	return &pkgCandidate{
		Product:        c.Product().String(),
		Vendor:         c.Vendor().String(),
		TargetSoftware: c.TargetSw().String(),
		PlatformCPE:    platformCPE,
	}, nil
}

func findUniquePkgs(tCfg Config, cfgs ...nvd.Configuration) uniquePkgTracker {
	set := newUniquePkgTracker()
	for _, c := range cfgs {
		_findUniquePkgs(tCfg, set, c)
	}
	return set
}

func platformPackageCandidates(tCfg Config, set uniquePkgTracker, c nvd.Configuration) bool {
	nodes := c.Nodes
	/*
		Turn a configuration like this:
		(AND
			(OR (cpe:2.3:a:redis:...whatever) (cpe:2.3.:something:...whatever)
			(OR (cpe:2.3:o:debian:9....) (cpe:2.3:o:ubuntu:22..))
		)
		Into a configuration like this:
		(OR
			(AND (cpe:2.3:a:redis:...whatever) (cpe:2.3:o:debian:9...))
			(AND (cpe:2.3:a:redis:...whatever) (cpe:2.3:o:ubuntu:22...))
			(AND (cpe:2.3:a:something:...whatever) (cpe:2.3:o:debian:9...))
			(AND (cpe:2.3:a:something:...whatever) (cpe:2.3:o:ubuntu:22...))
		)
		Because in schema v5, rows in Grype DB can only have zero or one platform CPE
		constraint.
	*/
	if len(nodes) != 2 || c.Operator == nil || *c.Operator != nvd.And {
		return false
	}
	var platformsNode nvd.Node
	var applicationNode nvd.Node
	for _, n := range nodes {
		if anyHardwareCPEPresent(n) {
			return false
		}
		if allCPEsVulnerable(n) {
			applicationNode = n
		}
		if noCPEsVulnerable(n) {
			platformsNode = n
		}
	}
	if platformsNode.Operator != nvd.Or {
		return false
	}
	if applicationNode.Operator != nvd.Or {
		return false
	}
	result := false
	matches := platformsNode.CpeMatch
	for _, application := range applicationNode.CpeMatch {
		for _, maybePlatform := range matches {
			platform := maybePlatform.Criteria
			candidate, err := newPkgCandidate(tCfg, application, platform)
			if err != nil {
				log.Debugf("unable processing uniquePkg with multiple platforms: %v", err)
				continue
			}
			if candidate == nil {
				continue
			}
			set.Add(*candidate, application)
			result = true
		}
	}
	return result
}

func anyHardwareCPEPresent(n nvd.Node) bool {
	for _, c := range n.CpeMatch {
		parts := strings.Split(c.Criteria, ":")
		if len(parts) < 3 || parts[2] == "h" {
			return true
		}
	}
	return false
}

func allCPEsVulnerable(node nvd.Node) bool {
	for _, c := range node.CpeMatch {
		if !c.Vulnerable {
			return false
		}
	}
	return true
}

func noCPEsVulnerable(node nvd.Node) bool {
	for _, c := range node.CpeMatch {
		if c.Vulnerable {
			return false
		}
	}
	return true
}

func _findUniquePkgs(tCfg Config, set uniquePkgTracker, c nvd.Configuration) {
	if len(c.Nodes) == 0 {
		return
	}

	if platformPackageCandidates(tCfg, set, c) {
		return
	}

	for _, node := range c.Nodes {
		for _, match := range node.CpeMatch {
			candidate, err := newPkgCandidate(tCfg, match, "")
			if err != nil {
				// Do not halt all execution because of being unable to create
				// a PkgCandidate. This can happen when a CPE is invalid which
				// could avoid creating a database
				log.Debugf("unable processing uniquePkg: %v", err)
				continue
			}
			if candidate != nil {
				set.Add(*candidate, match)
			}
		}
	}
}

func buildConstraints(matches []nvd.CpeMatch) string {
	constraints := make([]string, 0)
	for _, match := range matches {
		constraints = append(constraints, buildConstraint(match))
	}

	return versionutil.OrConstraints(removeDuplicateConstraints(constraints)...)
}

func buildConstraint(match nvd.CpeMatch) string {
	constraints := make([]string, 0)
	if match.VersionStartIncluding != nil && *match.VersionStartIncluding != "" {
		constraints = append(constraints, fmt.Sprintf(">= %s", *match.VersionStartIncluding))
	} else if match.VersionStartExcluding != nil && *match.VersionStartExcluding != "" {
		constraints = append(constraints, fmt.Sprintf("> %s", *match.VersionStartExcluding))
	}

	if match.VersionEndIncluding != nil && *match.VersionEndIncluding != "" {
		constraints = append(constraints, fmt.Sprintf("<= %s", *match.VersionEndIncluding))
	} else if match.VersionEndExcluding != nil && *match.VersionEndExcluding != "" {
		constraints = append(constraints, fmt.Sprintf("< %s", *match.VersionEndExcluding))
	}

	if len(constraints) == 0 {
		c, err := cpe.NewItemFromFormattedString(match.Criteria)
		if err != nil {
			return ""
		}
		version := c.Version().String()
		update := c.Update().String()
		if version != ANY && version != NA {
			if update != ANY && update != NA {
				version = fmt.Sprintf("%s-%s", version, update)
			}

			constraints = append(constraints, fmt.Sprintf("= %s", version))
		}
	}

	return strings.Join(constraints, ", ")
}

func removeDuplicateConstraints(constraints []string) []string {
	constraintMap := make(map[string]struct{})
	var uniqueConstraints []string
	for _, constraint := range constraints {
		if _, exists := constraintMap[constraint]; !exists {
			constraintMap[constraint] = struct{}{}
			uniqueConstraints = append(uniqueConstraints, constraint)
		}
	}
	return uniqueConstraints
}
