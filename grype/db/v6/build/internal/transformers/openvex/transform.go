package openvex

import (
	"fmt"
	"sort"

	govex "github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
	internal2 "github.com/anchore/grype/grype/db/v6/build/internal/transformers/internal"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/packageurl-go"
	syft "github.com/anchore/syft/syft/pkg"
)

func AnnotatedTransform(wrapper unmarshal.AnnotatedOpenVEXVulnerability, state provider.State) ([]data.Entry, error) {
	return transform(wrapper.Document, state, wrapper.Fixes)
}

func Transform(vulnerability unmarshal.OpenVEXVulnerability, state provider.State) ([]data.Entry, error) {
	return transform(vulnerability, state, nil)
}

func transform(vulnerability unmarshal.OpenVEXVulnerability, state provider.State, fixes []unmarshal.AnnotatedOpenVEXFix) ([]data.Entry, error) {
	name := getName(&vulnerability)
	vulnHandle := grypeDB.VulnerabilityHandle{
		Name:          name,
		Status:        grypeDB.VulnerabilityActive,
		PublishedDate: vulnerability.Timestamp,
		ModifiedDate:  vulnerability.LastUpdated,
		ProviderID:    state.Provider,
		Provider:      internal2.ProviderModel(state),
		BlobValue: &grypeDB.VulnerabilityBlob{
			ID:          name,
			Assigners:   nil,
			Description: vulnerability.Vulnerability.Description,
			References:  getReferences(&vulnerability),
			Aliases:     getAliases(&vulnerability),
		},
	}
	pkgs, err := getPackageHandles(&vulnerability, fixes)
	if err != nil {
		return nil, err
	}
	in := []any{vulnHandle}
	in = append(in, pkgs...)
	return transformers.NewEntries(in...), nil
}

// getPackageHandles for all products in this advisory
func getPackageHandles(vuln *unmarshal.OpenVEXVulnerability, fixes []unmarshal.AnnotatedOpenVEXFix) ([]any, error) {
	if len(vuln.Products) == 0 {
		return nil, nil
	}

	fixesByProduct := make(map[string][]unmarshal.AnnotatedOpenVEXFix)
	for _, fix := range fixes {
		fixesByProduct[fix.Product] = append(fixesByProduct[fix.Product], fix)
	}

	var aphs []grypeDB.AffectedPackageHandle
	var uaphs []grypeDB.UnaffectedPackageHandle
	for _, product := range vuln.Products {
		aph, uph, err := getPackageHandle(&product, vuln, fixesByProduct[product.Identifiers[govex.PURL]])
		if err != nil {
			return nil, err
		}
		aphs = append(aphs, aph...)
		uaphs = append(uaphs, uph...)
	}

	sort.Sort(internal2.ByAffectedPackage(aphs))
	sort.Sort(internal2.ByUnaffectedPackage(uaphs))

	var all []any
	for i := range aphs {
		all = append(all, aphs[i])
	}
	for i := range uaphs {
		all = append(all, uaphs[i])
	}

	return all, nil
}

// getPackageHandle for a single product
//
// OpenVEX defines product via:
//
//	Component {
//	  Identifiers: {
//	    PURLIdentifierType: pkg:type/name@version
//	  }
//	}
func getPackageHandle(product *govex.Product, vuln *unmarshal.OpenVEXVulnerability, fixes []unmarshal.AnnotatedOpenVEXFix) (aphs []grypeDB.AffectedPackageHandle, uphs []grypeDB.UnaffectedPackageHandle, err error) {
	if product == nil || vuln == nil {
		return nil, nil, fmt.Errorf("getAffectedPackage params cannot be nil")
	}
	purl, err := getPURL(product)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse purl %s: %w", purl, err)
	}

	pkg := &grypeDB.Package{
		Ecosystem: string(syft.TypeFromPURL(purl.String())),
		Name:      purl.Name,
	}

	aliases := []string{getName(vuln)}
	aliases = append(aliases, getAliases(vuln)...)

	switch vuln.Status {
	case govex.StatusAffected:
		aphs = append(aphs, grypeDB.AffectedPackageHandle{
			Package:   pkg,
			BlobValue: getPackageBlob(aliases, purl.Version, purl.Type, "", fixes),
		})
	case govex.StatusNotAffected:
		uphs = append(uphs, grypeDB.UnaffectedPackageHandle{
			Package:   pkg,
			BlobValue: getPackageBlob(aliases, purl.Version, purl.Type, grypeDB.NotAffectedFixStatus, fixes),
		})
	case govex.StatusFixed:
		uphs = append(uphs, grypeDB.UnaffectedPackageHandle{
			Package:   pkg,
			BlobValue: getPackageBlob(aliases, purl.Version, purl.Type, grypeDB.FixedStatus, fixes),
		})
	default:
		err = fmt.Errorf("invalid vuln states %s", vuln.Status)
	}
	return aphs, uphs, err
}

// getPURL from either ID field or identifiers
func getPURL(product *govex.Product) (purl *packageurl.PackageURL, err error) {
	if p, ok := product.Identifiers[govex.PURL]; ok {
		purl, err := packageurl.FromString(p)
		if err != nil {
			return nil, fmt.Errorf("failed to parse purl %s: %w", p, err)
		}
		return &purl, nil
	}
	if product.ID != "" {
		purl, err := packageurl.FromString(product.ID)
		if err != nil {
			return nil, err
		}
		return &purl, nil
	}
	return nil, fmt.Errorf("invalid product: %v", product)
}

func getAliases(vuln *unmarshal.OpenVEXVulnerability) []string {
	ret := make([]string, 0, len(vuln.Vulnerability.Aliases))
	for _, alias := range vuln.Vulnerability.Aliases {
		ret = append(ret, string(alias))
	}
	return ret
}

func getName(vuln *unmarshal.OpenVEXVulnerability) string {
	return string(vuln.Vulnerability.Name)
}

func getReferences(vuln *unmarshal.OpenVEXVulnerability) []grypeDB.Reference {
	refs := []grypeDB.Reference{
		{
			URL: getName(vuln),
		},
	}
	return refs
}

func getPackageBlob(aliases []string, ver string, ty string, fixState grypeDB.FixStatus, fixes []unmarshal.AnnotatedOpenVEXFix) *grypeDB.PackageBlob {
	var fix *grypeDB.Fix
	if fixState != "" {
		fix = &grypeDB.Fix{
			State: fixState,
		}

		canExpressFixVersion := ver != "" && fixState == grypeDB.FixedStatus
		if canExpressFixVersion {
			// only express a fix version if we have a version and the state is "fixed"
			fix.Version = ver
		}

		canExpressFixDetail := len(fixes) > 0 && canExpressFixVersion
		var detail *grypeDB.FixDetail
		if canExpressFixDetail {
			time := internal2.ParseTime(fixes[0].Available.Date)
			if time != nil && !time.IsZero() {
				detail = &grypeDB.FixDetail{
					Available: &grypeDB.FixAvailability{
						Date: time,
						Kind: fixes[0].Available.Kind,
					},
				}
			}
		}

		fix.Detail = detail
	}

	return &grypeDB.PackageBlob{
		CVEs: aliases,
		Ranges: []grypeDB.Range{
			{
				Version: grypeDB.Version{
					Type:       version.ParseFormat(ty).String(),
					Constraint: fmt.Sprintf("= %s", ver),
				},
				Fix: fix,
			},
		},
	}
}
