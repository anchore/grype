package v6

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/internal/architecture"
	"github.com/anchore/grype/internal/log"
)

// allowedArchitectures lists, per provider, the package architecture values a build accepts. A provider not
// listed may not emit any architecture. An architecture changes what a record means to the matchers (an
// arch-less record applies to every architecture), and older clients rely on rows staying arch-less, so a new
// provider or value is added here deliberately, together with matcher fixtures that exercise it.
var allowedArchitectures = map[string][]string{
	"chainguard":  {"x86_64", "aarch64"},
	"hummingbird": {architecture.ArchSource, architecture.ArchBinaryNoArchSpecified},
	"oracle":      {"x86_64", "aarch64"},
}

const (
	noArchitecture       = "(none)"
	maxViolationExamples = 3
)

// architectureTally counts the architecture of every package row by provider, and records the rows that
// break allowedArchitectures. Violations fail the build only once the summary is logged, so a failing
// build still shows everything that turned up.
type architectureTally struct {
	mu         sync.Mutex
	counts     map[string]map[string]int // provider -> architecture -> rows
	violations map[string][]string       // "provider/architecture" -> example vulnerabilities
}

func newArchitectureTally() *architectureTally {
	return &architectureTally{
		counts:     make(map[string]map[string]int),
		violations: make(map[string][]string),
	}
}

func (t *architectureTally) record(vulnHandle *db.VulnerabilityHandle, blob *db.PackageBlob) {
	var provider, vulnName string
	if vulnHandle != nil {
		provider, vulnName = vulnHandle.ProviderID, vulnHandle.Name
	}
	arch := noArchitecture
	if blob != nil && blob.Qualifiers != nil && blob.Qualifiers.Architecture != nil {
		arch = *blob.Qualifiers.Architecture
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.counts[provider] == nil {
		t.counts[provider] = make(map[string]int)
	}
	t.counts[provider][arch]++

	if arch == noArchitecture || slices.Contains(allowedArchitectures[provider], arch) {
		return
	}
	key := provider + "/" + arch
	if len(t.violations[key]) < maxViolationExamples && !slices.Contains(t.violations[key], vulnName) {
		t.violations[key] = append(t.violations[key], vulnName)
	}
}

// summarize logs the architecture counts of every provider that emitted any architecture, then returns an
// error naming each disallowed provider/architecture pair.
func (t *architectureTally) summarize() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, provider := range slices.Sorted(maps.Keys(t.counts)) {
		counts := t.counts[provider]
		if len(counts) == 1 && counts[noArchitecture] > 0 {
			continue // arch-less rows only, the norm
		}
		var parts []string
		for _, arch := range slices.Sorted(maps.Keys(counts)) {
			parts = append(parts, fmt.Sprintf("%s=%d", arch, counts[arch]))
		}
		log.WithFields("provider", provider, "architectures", strings.Join(parts, " ")).Info("package architectures")
	}

	if len(t.violations) == 0 {
		return nil
	}
	var parts []string
	for _, key := range slices.Sorted(maps.Keys(t.violations)) {
		provider, arch, _ := strings.Cut(key, "/")
		parts = append(parts, fmt.Sprintf("provider %q emitted architecture %q on %d rows (e.g. %s)",
			provider, arch, t.counts[provider][arch], strings.Join(t.violations[key], ", ")))
	}
	return fmt.Errorf("unexpected package architectures (see allowedArchitectures): %s", strings.Join(parts, "; "))
}
