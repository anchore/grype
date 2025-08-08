package csv

import (
	"encoding/csv"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

const (
	appendSuppressed    = "suppressed"
	appendSuppressedVEX = "suppressed by VEX"
)

type Presenter struct {
	document       models.Document
	showSuppressed bool
}

type rows []row

type row struct {
	Name            string
	Version         string
	Fix             string
	PackageType     string
	VulnerabilityID string
	Severity        string
	EPSS            epss
	Risk            string
	Annotation      string
}

type epss struct {
	Score      float64
	Percentile float64
}

func (e epss) String() string {
	percentile := e.Percentile * 100
	switch {
	case percentile == 0:
		return "N/A"
	case percentile < 0.1:
		return "< 0.1%"
	}
	return fmt.Sprintf("%.2f%%", percentile)
}

func NewPresenter(pb models.PresenterConfig, showSuppressed bool) *Presenter {
	return &Presenter{
		document:       pb.Document,
		showSuppressed: showSuppressed,
	}
}

func (p *Presenter) Present(output io.Writer) error {
	rs := p.getRows(p.document, p.showSuppressed)

	writer := csv.NewWriter(output)
	defer writer.Flush()

	if err := writer.Write([]string{"Name", "Installed", "Fixed-In", "Type", "Vulnerability", "Severity", "EPSS%", "Risk", "Annotations"}); err != nil {
		return err
	}

	if len(rs) == 0 {
		return nil
	}

	for _, row := range rs.Render() {
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (p *Presenter) getRows(doc models.Document, showSuppressed bool) rows {
	var rs rows

	multipleDistros := false
	existingDistro := ""
	for _, m := range doc.Matches {
		if _, err := distro.FromString(m.Vulnerability.Namespace); err == nil {
			if existingDistro == "" {
				existingDistro = m.Vulnerability.Namespace
			} else if existingDistro != m.Vulnerability.Namespace {
				multipleDistros = true
				break
			}
		}
	}

	for _, m := range doc.Matches {
		rs = append(rs, p.newRow(m, "", multipleDistros))
	}
	if showSuppressed {
		for _, m := range doc.IgnoredMatches {
			msg := appendSuppressed
			if m.AppliedIgnoreRules != nil {
				for i := range m.AppliedIgnoreRules {
					if m.AppliedIgnoreRules[i].Namespace == "vex" {
						msg = appendSuppressedVEX
					}
				}
			}
			rs = append(rs, p.newRow(m.Match, msg, multipleDistros))
		}
	}
	return rs
}

func (p *Presenter) newRow(m models.Match, extraAnnotation string, showDistro bool) row {
	var annotations []string

	if showDistro {
		if d, err := distro.FromString(m.Vulnerability.Namespace); err == nil {
			annotations = append(annotations, fmt.Sprintf("%s:%s", d.DistroType(), d.Version()))
		}
	}

	if extraAnnotation != "" {
		annotations = append(annotations, extraAnnotation)
	}

	var annotation string
	if len(m.Vulnerability.KnownExploited) > 0 {
		annotations = append([]string{"kev"}, annotations...)
	}

	if len(annotations) > 0 {
		annotation = "(" + strings.Join(annotations, ", ") + ")"
	}

	return row{
		Name:            m.Artifact.Name,
		Version:         m.Artifact.Version,
		Fix:             p.formatFix(m),
		PackageType:     string(m.Artifact.Type),
		VulnerabilityID: m.Vulnerability.ID,
		Severity:        m.Vulnerability.Severity,
		EPSS:            newEPSS(m.Vulnerability.EPSS),
		Risk:            p.formatRisk(m.Vulnerability.Risk),
		Annotation:      annotation,
	}
}

func newEPSS(es []models.EPSS) epss {
	if len(es) == 0 {
		return epss{}
	}
	return epss{
		Score:      es[0].EPSS,
		Percentile: es[0].Percentile,
	}
}

func (p *Presenter) formatRisk(risk float64) string {
	switch {
	case risk == 0:
		return "N/A"
	case risk < 0.1:
		return "< 0.1"
	}
	return fmt.Sprintf("%.1f", risk)
}

func (p *Presenter) formatFix(m models.Match) string {
	switch m.Vulnerability.Fix.State {
	case vulnerability.FixStateWontFix.String():
		return "(won't fix)"
	case vulnerability.FixStateUnknown.String():
		return ""
	}

	return p.applyTruncation(
		p.formatVersionsToDisplay(
			m,
			getRecommendedVersions(m),
		),
		m.Vulnerability.Fix.Versions,
	)
}

func getRecommendedVersions(m models.Match) *strset.Set {
	recommended := strset.New()
	for _, d := range m.MatchDetails {
		if d.Fix == nil {
			continue
		}
		if d.Fix.SuggestedVersion != "" {
			recommended.Add(d.Fix.SuggestedVersion)
		}
	}
	return recommended
}

const maxVersionFieldLength = 30

func (p *Presenter) formatVersionsToDisplay(m models.Match, recommendedVersions *strset.Set) []string {
	hasMultipleVersions := len(m.Vulnerability.Fix.Versions) > 1
	shouldHighlightRecommended := hasMultipleVersions && recommendedVersions.Size() > 0

	var currentCharacterCount int
	added := strset.New()
	var vers []string

	for _, v := range m.Vulnerability.Fix.Versions {
		if added.Has(v) {
			continue
		}

		if shouldHighlightRecommended {
			if recommendedVersions.Has(v) {
				added.Add(v)
				currentCharacterCount += len(v)
				vers = append(vers, v)
				continue
			}

			if currentCharacterCount+len(v) > maxVersionFieldLength {
				continue
			}

			currentCharacterCount += len(v)
			added.Add(v)
			vers = append(vers, v)
		} else {
			added.Add(v)
			vers = append(vers, v)
		}
	}

	return vers
}

func (p *Presenter) applyTruncation(formattedVersions []string, allVersions []string) string {
	finalVersions := strings.Join(formattedVersions, ", ")

	var characterCount int
	for _, v := range allVersions {
		characterCount += len(v)
	}

	if characterCount > maxVersionFieldLength && len(allVersions) > 1 {
		finalVersions += ", ..."
	}

	return finalVersions
}

func (r row) Columns() []string {
	columns := []string{
		stripANSI(r.Name),
		stripANSI(r.Version),
		stripANSI(r.Fix),
		stripANSI(r.PackageType),
		stripANSI(r.VulnerabilityID),
		stripANSI(r.Severity),
		stripANSI(r.EPSS.String()),
		stripANSI(r.Risk),
		stripANSI(r.Annotation),
	}

	return columns
}

func (r row) String() string {
	return strings.Join(r.Columns(), "|")
}

func (rs rows) Render() [][]string {
	deduped := rs.Deduplicate()
	out := make([][]string, len(deduped))
	for idx, r := range deduped {
		out[idx] = r.Columns()
	}
	return out
}

func (rs rows) Deduplicate() []row {
	seen := map[string]row{}
	var deduped rows

	for _, v := range rs {
		key := v.String()
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = v
		deduped = append(deduped, v)
	}

	return deduped
}

// stripANSI removes ANSI escape sequences from a string
func stripANSI(str string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(str, "")
}
