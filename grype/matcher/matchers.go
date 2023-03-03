package matcher

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	grypeDb "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/apk"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/msrc"
	"github.com/anchore/grype/grype/matcher/portage"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Monitor struct {
	PackagesProcessed         progress.Monitorable
	VulnerabilitiesDiscovered progress.Monitorable
	Fixed                     progress.Monitorable
	BySeverity                map[vulnerability.Severity]progress.Monitorable
}

type monitor struct {
	PackagesProcessed         *progress.Manual
	VulnerabilitiesDiscovered *progress.Manual
	Fixed                     *progress.Manual
	BySeverity                map[vulnerability.Severity]*progress.Manual
}

func newMonitor() (monitor, Monitor) {
	manualBySev := make(map[vulnerability.Severity]*progress.Manual)
	for _, severity := range vulnerability.AllSeverities() {
		manualBySev[severity] = progress.NewManual(-1)
	}
	manualBySev[vulnerability.UnknownSeverity] = progress.NewManual(-1)

	m := monitor{
		PackagesProcessed:         progress.NewManual(-1),
		VulnerabilitiesDiscovered: progress.NewManual(-1),
		Fixed:                     progress.NewManual(-1),
		BySeverity:                manualBySev,
	}

	monitorableBySev := make(map[vulnerability.Severity]progress.Monitorable)
	for sev, manual := range manualBySev {
		monitorableBySev[sev] = manual
	}

	return m, Monitor{
		PackagesProcessed:         m.PackagesProcessed,
		VulnerabilitiesDiscovered: m.VulnerabilitiesDiscovered,
		Fixed:                     m.Fixed,
		BySeverity:                monitorableBySev,
	}
}

func (m *monitor) SetCompleted() {
	m.PackagesProcessed.SetCompleted()
	m.VulnerabilitiesDiscovered.SetCompleted()
	m.Fixed.SetCompleted()
	for _, v := range m.BySeverity {
		v.SetCompleted()
	}
}

// Config contains values used by individual matcher structs for advanced configuration
type Config struct {
	Java       java.MatcherConfig
	Ruby       ruby.MatcherConfig
	Python     python.MatcherConfig
	Dotnet     dotnet.MatcherConfig
	Javascript javascript.MatcherConfig
	Golang     golang.MatcherConfig
	Stock      stock.MatcherConfig
}

func NewDefaultMatchers(mc Config) []Matcher {
	return []Matcher{
		&dpkg.Matcher{},
		ruby.NewRubyMatcher(mc.Ruby),
		python.NewPythonMatcher(mc.Python),
		dotnet.NewDotnetMatcher(mc.Dotnet),
		&rpm.Matcher{},
		java.NewJavaMatcher(mc.Java),
		javascript.NewJavascriptMatcher(mc.Javascript),
		&apk.Matcher{},
		golang.NewGolangMatcher(mc.Golang),
		&msrc.Matcher{},
		&portage.Matcher{},
		stock.NewStockMatcher(mc.Stock),
	}
}

func trackMatcher() *monitor {
	writer, reader := newMonitor()

	bus.Publish(partybus.Event{
		Type:  event.VulnerabilityScanningStarted,
		Value: reader,
	})

	return &writer
}

func newMatcherIndex(matchers []Matcher) (map[syftPkg.Type][]Matcher, Matcher) {
	matcherIndex := make(map[syftPkg.Type][]Matcher)
	var defaultMatcher Matcher
	for _, m := range matchers {
		if m.Type() == match.StockMatcher {
			defaultMatcher = m
			continue
		}
		for _, t := range m.PackageTypes() {
			if _, ok := matcherIndex[t]; !ok {
				matcherIndex[t] = make([]Matcher, 0)
			}

			matcherIndex[t] = append(matcherIndex[t], m)
			log.Debugf("adding matcher: %+v", t)
		}
	}

	return matcherIndex, defaultMatcher
}

func FindMatches(store interface {
	vulnerability.Provider
	vulnerability.MetadataProvider
	match.ExclusionProvider
}, release *linux.Release, matchers []Matcher, packages []pkg.Package) match.Matches {
	var err error
	res := match.NewMatches()
	matcherIndex, defaultMatcher := newMatcherIndex(matchers)

	var d *distro.Distro
	if release != nil {
		d, err = distro.NewFromRelease(*release)
		if err != nil {
			log.Warnf("unable to determine linux distribution: %+v", err)
		}
		if d != nil && d.Disabled() {
			log.Warnf("unsupported linux distribution: %s", d.Name())
			return match.Matches{}
		}
	}

	progressMonitor := trackMatcher()

	if defaultMatcher == nil {
		defaultMatcher = stock.NewStockMatcher(stock.MatcherConfig{UseCPEs: true})
	}
	for _, p := range packages {
		progressMonitor.PackagesProcessed.Increment()
		log.Debugf("searching for vulnerability matches for pkg=%s", p)

		matchAgainst, ok := matcherIndex[p.Type]
		if !ok {
			matchAgainst = []Matcher{defaultMatcher}
		}
		for _, m := range matchAgainst {
			matches, err := m.Match(store, d, p)
			if err != nil {
				log.Warnf("matcher failed for pkg=%s: %+v", p, err)
			} else {
				logMatches(p, matches)
				res.Add(matches...)
				progressMonitor.VulnerabilitiesDiscovered.Add(int64(len(matches)))
				updateVulnerabilityList(progressMonitor, matches, store)
			}
		}
	}

	progressMonitor.SetCompleted()

	logListSummary(progressMonitor)

	// Filter out matches based off of the records in the exclusion table in the database or from the old hard-coded rules
	res = match.ApplyExplicitIgnoreRules(store, res)

	return res
}

func logListSummary(vl *monitor) {
	log.Infof("found %d vulnerabilities for %d packages", vl.VulnerabilitiesDiscovered.Current(), vl.PackagesProcessed.Current())
	log.Debugf("  ├── fixed: %d", vl.Fixed.Current())
	log.Debugf("  └── matched: %d", vl.VulnerabilitiesDiscovered.Current())

	var unknownCount int64
	if count, ok := vl.BySeverity[vulnerability.UnknownSeverity]; ok {
		unknownCount = count.Current()
	}
	log.Debugf("      ├── %s: %d", vulnerability.UnknownSeverity.String(), unknownCount)

	allSeverities := vulnerability.AllSeverities()
	for idx, sev := range allSeverities {
		branch := "├"
		if idx == len(allSeverities)-1 {
			branch = "└"
		}
		log.Debugf("      %s── %s: %d", branch, sev.String(), vl.BySeverity[sev].Current())
	}
}

func updateVulnerabilityList(list *monitor, matches []match.Match, metadataProvider vulnerability.MetadataProvider) {
	for _, m := range matches {
		metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
		if err != nil || metadata == nil {
			list.BySeverity[vulnerability.UnknownSeverity].Increment()
			continue
		}

		sevManualProgress, ok := list.BySeverity[vulnerability.ParseSeverity(metadata.Severity)]
		if !ok {
			list.BySeverity[vulnerability.UnknownSeverity].Increment()
			continue
		}
		sevManualProgress.Increment()

		if m.Vulnerability.Fix.State == grypeDb.FixedState {
			list.Fixed.Increment()
		}
	}
}

func logMatches(p pkg.Package, matches []match.Match) {
	if len(matches) > 0 {
		log.Debugf("found %d vulnerabilities for pkg=%s", len(matches), p)
		for idx, m := range matches {
			var branch = "├──"
			if idx == len(matches)-1 {
				branch = "└──"
			}
			log.Debugf("  %s %s", branch, m.Summary())
		}
	}
}
