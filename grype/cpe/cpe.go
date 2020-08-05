package cpe

import (
	"fmt"

	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

// TODO: would be great to allow these to be overridden by user data/config
var targetSoftware = map[pkg.Language][]string{
	pkg.Java: {
		"java",
		"maven",
		"jenkins",
		"cloudbees_jenkins",
	},
	//pkg.JavaScript: {
	//	"node.js",
	//},
	pkg.Python: {
		"python",
	},
	pkg.Ruby: {
		"ruby",
		"rails",
	},
}

const ANY = "*"

type CPE = wfn.Attributes

func New(cpeStr string) (CPE, error) {
	value, err := wfn.Parse(cpeStr)
	// we need to compare the raw data since we are constructing CPEs in other locations
	value.Vendor = wfn.StripSlashes(value.Vendor)
	value.Product = wfn.StripSlashes(value.Product)
	value.Language = wfn.StripSlashes(value.Language)
	value.Version = wfn.StripSlashes(value.Version)
	value.TargetSW = wfn.StripSlashes(value.TargetSW)
	value.Part = wfn.StripSlashes(value.Part)
	value.Edition = wfn.StripSlashes(value.Edition)
	value.Other = wfn.StripSlashes(value.Other)
	value.SWEdition = wfn.StripSlashes(value.SWEdition)
	value.TargetHW = wfn.StripSlashes(value.TargetHW)
	value.Update = wfn.StripSlashes(value.Update)

	if value == nil || err != nil {
		return CPE{}, fmt.Errorf("failed to parse CPE (%s): %w", cpeStr, err)
	}
	return *value, nil
}

func NewSlice(cpeStrs ...string) ([]CPE, error) {
	ret := make([]CPE, len(cpeStrs))
	for idx, c := range cpeStrs {
		value, err := New(c)
		if err != nil {
			return nil, err
		}
		ret[idx] = value
	}
	return ret, nil
}

// Generate Create a list of CPEs, trying to guess the vendor, product tuple and setting TargetSoftware if possible
func Generate(p *pkg.Package) ([]CPE, error) {
	targetSoftwares := candidateTargetSoftwareAttrs(p)
	vendors := candidateVendors(p)
	products := candidateProducts(p)

	keys := internal.NewStringSet()
	cpes := make([]CPE, 0)
	for _, product := range products {
		for _, vendor := range vendors {
			for _, targetSw := range targetSoftwares {
				// prevent duplicate entries...
				key := fmt.Sprintf("%s|%s|%s|%s", product, vendor, p.Version, targetSw)
				if keys.Contains(key) {
					continue
				}
				keys.Add(key)

				// add a new entry...
				candidateCpe := wfn.NewAttributesWithAny()
				candidateCpe.Product = product
				candidateCpe.Vendor = vendor
				candidateCpe.Version = p.Version
				candidateCpe.TargetSW = targetSw

				cpes = append(cpes, *candidateCpe)
			}
		}
	}

	return cpes, nil
}

func candidateTargetSoftwareAttrs(p *pkg.Package) []string {
	// TODO: expand with package metadata (from type assert)
	mappedNames := targetSoftware[p.Language]

	if mappedNames == nil {
		mappedNames = []string{}
	}

	attrs := make([]string, len(mappedNames))
	copy(attrs, targetSoftware[p.Language])
	// last element is the any match, present for all
	attrs = append(attrs, ANY)

	return attrs
}

func candidateVendors(p *pkg.Package) []string {
	// TODO: expand with package metadata (from type assert)
	ret := []string{p.Name, ANY}
	if p.Language == pkg.Python {
		ret = append(ret, fmt.Sprintf("python-%s", p.Name))
	}
	return ret
}

func candidateProducts(p *pkg.Package) []string {
	// TODO: expand with package metadata (from type assert)
	return []string{p.Name}
}

func MatchWithoutVersion(c CPE, candidates []CPE) []CPE {
	results := make([]CPE, 0)
	for _, candidate := range candidates {
		canCopy := candidate
		if c.MatchWithoutVersion(&canCopy) {
			results = append(results, candidate)
		}
	}
	return results
}
