package csafvex

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/packageurl-go"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func Transform(advisory unmarshal.CSAFVEXAdvisory, state provider.State) ([]data.Entry, error) {
	// build product ID → PURL/CPE lookup from product tree
	productIndex := newProductIndex(&advisory.ProductTree)

	var allEntries []data.Entry

	for i := range advisory.Vulnerabilites {
		vuln := &advisory.Vulnerabilites[i]
		entries, err := transformVulnerability(vuln, &advisory, productIndex, state)
		if err != nil {
			return nil, fmt.Errorf("failed to transform vulnerability %s: %w", vuln.CVE, err)
		}
		allEntries = append(allEntries, entries...)
	}

	return allEntries, nil
}

func transformVulnerability(vuln *unmarshal.CSAFVulnerability, advisory *unmarshal.CSAFVEXAdvisory, idx *productIndex, state provider.State) ([]data.Entry, error) {
	vulnName := vuln.CVE

	severities := getSeverities(vuln)
	description := getDescription(vuln)
	references := getReferences(vuln, advisory)

	vulnHandle := db.VulnerabilityHandle{
		Name:          vulnName,
		Status:        db.VulnerabilityActive,
		PublishedDate: internal.ParseTime(vuln.ReleaseDate),
		ModifiedDate:  internal.ParseTime(advisory.Document.Tracking.CurrentReleaseDate),
		ProviderID:    state.Provider,
		Provider:      provider.Model(state),
		BlobValue: &db.VulnerabilityBlob{
			ID:          strings.ToLower(vulnName),
			Description: description,
			References:  references,
			Severities:  severities,
		},
	}

	pkgs, err := getPackageHandles(vuln, idx)
	if err != nil {
		return nil, err
	}

	in := []any{vulnHandle}
	in = append(in, pkgs...)

	return transformers.NewEntries(in...), nil
}

// ── product tree indexing ────────────────────────────────────────────

// productIndex maps product IDs to their PURL, CPE, and platform context
// by walking the product tree branches and relationships.
type productIndex struct {
	// productIDToPURL maps a product_id to a parsed PURL (from branches or relationships)
	productIDToPURL map[string]*packageurl.PackageURL

	// productIDToCPE maps a product_id to a CPE string
	productIDToCPE map[string]string

	// relationshipPlatform maps a relationship full_product_name.product_id to the
	// platform product_id it relates to (relates_to_product_reference)
	relationshipPlatform map[string]string
}

func newProductIndex(tree *unmarshal.CSAFProductTree) *productIndex {
	idx := &productIndex{
		productIDToPURL:      make(map[string]*packageurl.PackageURL),
		productIDToCPE:       make(map[string]string),
		relationshipPlatform: make(map[string]string),
	}

	// walk branches to collect PURLs and CPEs
	for _, b := range tree.Branches {
		idx.indexBranch(&b)
	}

	// walk relationships to collect composed product IDs
	for _, rel := range tree.Relationships {
		fpn := rel.FullProductName
		if fpn.ProductID == "" {
			continue
		}

		// the relationship's full_product_name inherits the PURL from the product_reference
		if purl, ok := idx.productIDToPURL[rel.ProductReference]; ok {
			idx.productIDToPURL[fpn.ProductID] = purl
		}
		if cpe, ok := idx.productIDToCPE[rel.ProductReference]; ok {
			idx.productIDToCPE[fpn.ProductID] = cpe
		}

		// track which platform this composed product relates to
		idx.relationshipPlatform[fpn.ProductID] = rel.RelatesToProductReference
	}

	return idx
}

func (idx *productIndex) indexBranch(b *unmarshal.CSAFBranch) {
	if b.Product != nil && b.Product.ProductID != "" {
		helper := b.Product.ProductIdentificationHelper
		if helper != nil {
			if helper.PURL != "" {
				if purl, err := packageurl.FromString(helper.PURL); err == nil {
					idx.productIDToPURL[b.Product.ProductID] = &purl
				}
			}
			if helper.CPE != "" {
				idx.productIDToCPE[b.Product.ProductID] = helper.CPE
			}
		}
	}
	for i := range b.Branches {
		idx.indexBranch(&b.Branches[i])
	}
}

// ── package handles ──────────────────────────────────────────────────

func getPackageHandles(vuln *unmarshal.CSAFVulnerability, idx *productIndex) ([]any, error) {
	if vuln.ProductStatus == nil {
		return nil, nil
	}

	// build a set of product IDs that have a vendor_fix remediation, and their fix URLs
	remediationsByProduct := buildRemediationIndex(vuln.Remediations)

	var aphs []db.AffectedPackageHandle
	var uphs []db.UnaffectedPackageHandle

	// known_affected → AffectedPackageHandle
	for _, pid := range vuln.ProductStatus.KnownAffected {
		aph, err := makeAffectedHandle(pid, vuln, idx, remediationsByProduct)
		if err != nil {
			continue // skip products we can't resolve
		}
		aphs = append(aphs, *aph)
	}

	// fixed → AffectedPackageHandle with fix version (package was affected, fix is available)
	for _, pid := range vuln.ProductStatus.Fixed {
		aph, err := makeFixedHandle(pid, vuln, idx, remediationsByProduct)
		if err != nil {
			continue
		}
		aphs = append(aphs, *aph)
	}

	// known_not_affected → UnaffectedPackageHandle
	for _, pid := range vuln.ProductStatus.KnownNotAffected {
		uph, err := makeUnaffectedHandle(pid, vuln, idx, db.NotAffectedFixStatus, remediationsByProduct)
		if err != nil {
			continue
		}
		uphs = append(uphs, *uph)
	}

	sort.Sort(internal.ByAffectedPackage(aphs))
	sort.Sort(internal.ByUnaffectedPackage(uphs))

	var all []any
	for i := range aphs {
		all = append(all, aphs[i])
	}
	for i := range uphs {
		all = append(all, uphs[i])
	}

	return all, nil
}

func makeAffectedHandle(productID string, vuln *unmarshal.CSAFVulnerability, idx *productIndex, remediations map[string]*unmarshal.CSAFRemediation) (*db.AffectedPackageHandle, error) {
	purl, ok := idx.productIDToPURL[productID]
	if !ok {
		return nil, fmt.Errorf("no PURL for product ID %s", productID)
	}

	pkgType := syftPkg.TypeFromPURL(purl.String())
	pkg := &db.Package{
		Ecosystem: string(pkgType),
		Name:      name.Normalize(purl.Name, pkgType),
	}

	os := getOperatingSystem(productID, idx)

	// for affected packages, look for a vendor_fix remediation to find the fix version
	blob := &db.PackageBlob{
		CVEs: []string{vuln.CVE},
	}

	rem := remediations[productID]
	if rem != nil && rem.URL != "" {
		blob.Ranges = []db.Range{
			{
				Version: db.Version{
					Type:       versionTypeFromPURL(purl),
					Constraint: fmt.Sprintf("< %s", purl.Version),
				},
				Fix: &db.Fix{
					State: db.NotFixedStatus,
					Detail: &db.FixDetail{
						References: []db.Reference{
							{URL: rem.URL, Tags: []string{db.AdvisoryReferenceTag}},
						},
					},
				},
			},
		}
	}

	return &db.AffectedPackageHandle{
		Package:         pkg,
		OperatingSystem: os,
		BlobValue:       blob,
	}, nil
}

func makeFixedHandle(productID string, vuln *unmarshal.CSAFVulnerability, idx *productIndex, remediations map[string]*unmarshal.CSAFRemediation) (*db.AffectedPackageHandle, error) {
	purl, ok := idx.productIDToPURL[productID]
	if !ok {
		return nil, fmt.Errorf("no PURL for product ID %s", productID)
	}

	pkgType := syftPkg.TypeFromPURL(purl.String())
	pkg := &db.Package{
		Ecosystem: string(pkgType),
		Name:      name.Normalize(purl.Name, pkgType),
	}

	os := getOperatingSystem(productID, idx)

	fix := &db.Fix{
		Version: purl.Version,
		State:   db.FixedStatus,
	}

	// attach fix date from remediation if available
	rem := remediations[productID]
	if rem != nil && rem.Date != "" {
		t := internal.ParseTime(rem.Date)
		if t != nil {
			fix.Detail = &db.FixDetail{
				Available: &db.FixAvailability{
					Date: t,
					Kind: "advisory",
				},
			}
		}
	}

	return &db.AffectedPackageHandle{
		Package:         pkg,
		OperatingSystem: os,
		BlobValue: &db.PackageBlob{
			CVEs: []string{vuln.CVE},
			Ranges: []db.Range{
				{
					Version: db.Version{
						Type:       versionTypeFromPURL(purl),
						Constraint: fmt.Sprintf("< %s", purl.Version),
					},
					Fix: fix,
				},
			},
		},
	}, nil
}

func makeUnaffectedHandle(productID string, vuln *unmarshal.CSAFVulnerability, idx *productIndex, fixState db.FixStatus, remediations map[string]*unmarshal.CSAFRemediation) (*db.UnaffectedPackageHandle, error) {
	purl, ok := idx.productIDToPURL[productID]
	if !ok {
		return nil, fmt.Errorf("no PURL for product ID %s", productID)
	}

	pkgType := syftPkg.TypeFromPURL(purl.String())
	pkg := &db.Package{
		Ecosystem: string(pkgType),
		Name:      name.Normalize(purl.Name, pkgType),
	}

	os := getOperatingSystem(productID, idx)

	fix := &db.Fix{
		State: fixState,
	}

	if fixState == db.FixedStatus && purl.Version != "" {
		fix.Version = purl.Version

		// attach fix date from remediation if available
		rem := remediations[productID]
		if rem != nil && rem.Date != "" {
			t := internal.ParseTime(rem.Date)
			if t != nil {
				fix.Detail = &db.FixDetail{
					Available: &db.FixAvailability{
						Date: t,
						Kind: "advisory",
					},
				}
			}
		}
	}

	constraint := fmt.Sprintf("< %s", purl.Version)
	if fixState == db.NotAffectedFixStatus {
		constraint = fmt.Sprintf("= %s", purl.Version)
	}

	return &db.UnaffectedPackageHandle{
		Package:         pkg,
		OperatingSystem: os,
		BlobValue: &db.PackageBlob{
			CVEs: []string{vuln.CVE},
			Ranges: []db.Range{
				{
					Version: db.Version{
						Type:       versionTypeFromPURL(purl),
						Constraint: constraint,
					},
					Fix: fix,
				},
			},
		},
	}, nil
}

// ── helpers ──────────────────────────────────────────────────────────

func buildRemediationIndex(remediations []unmarshal.CSAFRemediation) map[string]*unmarshal.CSAFRemediation {
	out := make(map[string]*unmarshal.CSAFRemediation)
	for i := range remediations {
		rem := &remediations[i]
		if rem.Category != "vendor_fix" {
			continue
		}
		for _, pid := range rem.ProductIDs {
			out[pid] = rem
		}
	}
	return out
}

func getOperatingSystem(productID string, idx *productIndex) *db.OperatingSystem {
	// look up the platform this product relates to via relationship
	platformID, ok := idx.relationshipPlatform[productID]
	if !ok {
		return nil
	}

	cpe, ok := idx.productIDToCPE[platformID]
	if !ok {
		return nil
	}

	return osFromCPE(cpe)
}

// osFromCPE extracts OS name and version from a CPE string.
// Example: "cpe:/a:redhat:hummingbird:1" → name=hummingbird, majorVersion=1
// Example: "cpe:/o:redhat:enterprise_linux:9" → name=redhat:enterprise_linux, majorVersion=9
func osFromCPE(cpe string) *db.OperatingSystem {
	// handle both cpe:/ and cpe:2.3: formats
	var parts []string
	if strings.HasPrefix(cpe, "cpe:/") {
		// URI format: cpe:/part:vendor:product:version
		remainder := strings.TrimPrefix(cpe, "cpe:/")
		parts = strings.Split(remainder, ":")
	} else if strings.HasPrefix(cpe, "cpe:2.3:") {
		// formatted string: cpe:2.3:part:vendor:product:version:...
		remainder := strings.TrimPrefix(cpe, "cpe:2.3:")
		parts = strings.Split(remainder, ":")
	} else {
		return nil
	}

	// parts[0]=part, parts[1]=vendor, parts[2]=product, parts[3]=version (optional)
	if len(parts) < 3 {
		return nil
	}

	osName := parts[2]

	os := &db.OperatingSystem{
		Name: strings.ToLower(osName),
	}

	if len(parts) > 3 && parts[3] != "" && parts[3] != "*" {
		versionParts := strings.SplitN(parts[3], ".", 2)
		os.MajorVersion = versionParts[0]
		if len(versionParts) > 1 {
			os.MinorVersion = versionParts[1]
		}
	}

	return os
}

func versionTypeFromPURL(purl *packageurl.PackageURL) string {
	return strings.ToLower(version.ParseFormat(purl.Type).String())
}

func getDescription(vuln *unmarshal.CSAFVulnerability) string {
	for _, note := range vuln.Notes {
		if note.Category == "description" {
			return note.Text
		}
	}
	return vuln.Title
}

func getReferences(vuln *unmarshal.CSAFVulnerability, advisory *unmarshal.CSAFVEXAdvisory) []db.Reference {
	var refs []db.Reference

	for _, ref := range vuln.References {
		tags := db.NormalizeReferenceTags([]string{ref.Category})
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: tags,
		})
	}

	// add the advisory tracking ID as a reference
	trackingID := advisory.Document.Tracking.ID
	if trackingID != "" {
		for _, ref := range advisory.Document.References {
			if ref.Category == "self" {
				refs = append(refs, db.Reference{
					URL:  ref.URL,
					ID:   trackingID,
					Tags: []string{db.AdvisoryReferenceTag},
				})
				break
			}
		}
	}

	return transformers.DeduplicateReferences(refs)
}

func getSeverities(vuln *unmarshal.CSAFVulnerability) []db.Severity {
	var severities []db.Severity

	for _, score := range vuln.Scores {
		if score.CVSSV3 != nil {
			severities = append(severities, db.Severity{
				Scheme: db.SeveritySchemeCVSS,
				Value: db.CVSSSeverity{
					Vector:  score.CVSSV3.VectorString,
					Version: score.CVSSV3.Version,
				},
			})
		}
		if score.CVSSV2 != nil {
			severities = append(severities, db.Severity{
				Scheme: db.SeveritySchemeCVSS,
				Value: db.CVSSSeverity{
					Vector:  score.CVSSV2.VectorString,
					Version: score.CVSSV2.Version,
				},
			})
		}
	}

	return severities
}
