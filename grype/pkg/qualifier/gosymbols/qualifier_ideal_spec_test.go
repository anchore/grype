package gosymbols

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

// This file is an executable SPEC of the IDEAL (most-correct) behavior of the gosymbols qualifier,
// NOT a description of current behavior. Some rows are EXPECTED TO FAIL against the implementation as
// it stands today; those failures are the point of the file.
//
// Rows tagged FN-RISK assert satisfied=true for an import-scoped advisory when the scanned module
// carries NO symbol evidence. The current implementation suppresses (returns satisfied=false) in that
// case, so those rows FAIL. That suppression silently drops real, fixable vulnerabilities on every
// route where symbols are legitimately absent even though the advisory genuinely applies:
//   - SBOM generated without symbol capture (syft's default; symbols simply not present)
//   - symbol capture disabled at scan time
//   - stdlib-only capture scope, which leaves non-stdlib modules with empty symbol maps
//
// Guiding principle encoded here: suppress a match ONLY when we have symbol coverage for THIS module
// AND the vulnerable path/symbol is absent from it (evidence of absence). When the module carries no
// symbol evidence at all we cannot prove the vulnerable code is unused, so the correct answer is a
// module-level match (satisfied=true) to preserve recall. Absence of evidence is not evidence of
// absence.
//
// Route modeling with the current API:
//   - "covered + used":     non-empty Symbols map containing the vulnerable path + vulnerable local symbol(s) -> true
//   - "covered + not used": non-empty Symbols map with sibling paths/symbols of the same module only         -> false (FP correctly avoided)
//   - "no symbol evidence": empty Symbols map (pkg.GolangBinMetadata{})                                       -> true (module-level fallback; FN avoided)
func TestGoSymbolsQualifier_IdealSpec_RealAdvisories(t *testing.T) {
	// symbol maps are keyed by import path; values are LOCAL symbol names (import-path prefix stripped),
	// already normalized to govulndb's convention (as the provider delivers them).
	pkgWithSymbols := func(name string, symbols map[string][]string) pkg.Package {
		return pkg.Package{Name: name, Metadata: pkg.GolangBinMetadata{Symbols: symbols}}
	}
	noSymbols := func(name string) pkg.Package {
		return pkg.Package{Name: name, Metadata: pkg.GolangBinMetadata{}}
	}

	// GO-2026-5932: golang.org/x/crypto/openpgp is unmaintained/unsafe. Whole-package scoping (no
	// symbols on the advisory) across every openpgp subpackage. This advisory is the FALSE-POSITIVE
	// source: module-level matching flags any x/crypto consumer, even ones that only touch ssh.
	openpgpVuln := []Import{
		{Path: "golang.org/x/crypto/openpgp"},
		{Path: "golang.org/x/crypto/openpgp/packet"},
		{Path: "golang.org/x/crypto/openpgp/armor"},
		{Path: "golang.org/x/crypto/openpgp/clearsign"},
		{Path: "golang.org/x/crypto/openpgp/errors"},
		{Path: "golang.org/x/crypto/openpgp/elgamal"},
		{Path: "golang.org/x/crypto/openpgp/s2k"},
	}

	// GO-2024-3321 / CVE-2024-45337: golang.org/x/crypto/ssh authorization bypass (fixed 0.31.0). A
	// real, fixable, high-severity vuln scoped to specific ssh server symbols. This is the
	// FALSE-NEGATIVE source: suppressing it when symbols are absent silently drops an auth-bypass.
	sshAuthBypassVuln := []Import{{
		Path:    "golang.org/x/crypto/ssh",
		Symbols: []string{"NewServerConn", "ServerConfig.PublicKeyCallback", "connection.serverAuthenticate"},
	}}

	// GO-2025-3595 / CVE-2025-22872: golang.org/x/net/html (fixed 0.38.0).
	netHTMLVuln := []Import{{
		Path:    "golang.org/x/net/html",
		Symbols: []string{"Parse", "ParseFragment", "ParseFragmentWithOptions", "ParseWithOptions", "Tokenizer.Next", "Tokenizer.readStartTag"},
	}}

	// GO-2026-4602 / CVE-2026-27139: stdlib os.Root escape (fixed 1.25.8/1.26.1). stdlib scope, so
	// affects nearly every binary built with an older toolchain.
	osRootEscapeVuln := []Import{{
		Path:    "os",
		Symbols: []string{"File.ReadDir", "File.Readdir", "ReadDir", "dirFS.ReadDir", "rootFS.ReadDir"},
	}}

	// GO-2022-0969 / CVE-2022-27664: stdlib net/http server DoS. Server-side entrypoints only.
	httpServerDoSVuln := []Import{{
		Path: "net/http",
		Symbols: []string{
			"ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS",
			"Server.ListenAndServe", "Server.ListenAndServeTLS", "Server.Serve", "Server.ServeTLS",
			"http2Server.ServeConn", "http2serverConn.goAway",
		},
	}}

	tests := []struct {
		name          string
		advisoryID    string
		route         string
		imports       []Import
		pkg           pkg.Package
		wantSatisfied bool
		fpOrFn        string
	}{
		// --- GO-2026-5932: openpgp whole-package (FP source) ---
		{
			name:          "GO-2026-5932 openpgp / covered+used: binary genuinely links openpgp -> match",
			advisoryID:    "GO-2026-5932",
			route:         "covered+used",
			imports:       openpgpVuln,
			pkg:           pkgWithSymbols("golang.org/x/crypto", map[string][]string{"golang.org/x/crypto/openpgp": {"ReadMessage", "ArmoredDetachSign"}}),
			wantSatisfied: true,
			fpOrFn:        "correct positive: openpgp actually used",
		},
		{
			name:          "GO-2026-5932 openpgp / covered+not-used: binary links only ssh (issue #3573) -> no match",
			advisoryID:    "GO-2026-5932",
			route:         "covered+not-used",
			imports:       openpgpVuln,
			pkg:           pkgWithSymbols("golang.org/x/crypto", map[string][]string{"golang.org/x/crypto/ssh": {"Dial", "NewClientConn"}}),
			wantSatisfied: false,
			fpOrFn:        "FP correctly avoided: openpgp not used, coverage proves absence",
		},
		{
			name:          "GO-2026-5932 openpgp / no-symbol-evidence: SBOM without symbols -> module fallback match",
			advisoryID:    "GO-2026-5932",
			route:         "no-symbol-evidence",
			imports:       openpgpVuln,
			pkg:           noSymbols("golang.org/x/crypto"),
			wantSatisfied: true,
			fpOrFn:        "FN-tradeoff: openpgp FP is the acceptable price of not knowing; the real fix is guaranteeing coverage, not guessing absence",
		},

		// --- GO-2024-3321 / CVE-2024-45337: x/crypto/ssh auth bypass (FN source) ---
		{
			name:          "GO-2024-3321 ssh-authz / covered+used: vulnerable server symbol present -> match",
			advisoryID:    "GO-2024-3321",
			route:         "covered+used",
			imports:       sshAuthBypassVuln,
			pkg:           pkgWithSymbols("golang.org/x/crypto", map[string][]string{"golang.org/x/crypto/ssh": {"NewServerConn", "ServerConfig.PublicKeyCallback"}}),
			wantSatisfied: true,
			fpOrFn:        "correct positive: vulnerable ssh server symbol used",
		},
		{
			name:          "GO-2024-3321 ssh-authz / covered+not-used: client-only ssh symbols -> no match",
			advisoryID:    "GO-2024-3321",
			route:         "covered+not-used",
			imports:       sshAuthBypassVuln,
			pkg:           pkgWithSymbols("golang.org/x/crypto", map[string][]string{"golang.org/x/crypto/ssh": {"Dial", "NewClientConn", "ClientConfig"}}),
			wantSatisfied: false,
			fpOrFn:        "FP correctly avoided: only client-side ssh symbols used",
		},
		{
			name:          "GO-2024-3321 ssh-authz / no-symbol-evidence: SBOM without symbols -> module fallback match",
			advisoryID:    "GO-2024-3321",
			route:         "no-symbol-evidence",
			imports:       sshAuthBypassVuln,
			pkg:           noSymbols("golang.org/x/crypto"),
			wantSatisfied: true,
			fpOrFn:        "FN-RISK: current PR suppresses -> silent auth-bypass miss",
		},

		// --- GO-2025-3595 / CVE-2025-22872: x/net/html ---
		{
			name:          "GO-2025-3595 net/html / covered+used: Parse present -> match",
			advisoryID:    "GO-2025-3595",
			route:         "covered+used",
			imports:       netHTMLVuln,
			pkg:           pkgWithSymbols("golang.org/x/net", map[string][]string{"golang.org/x/net/html": {"Parse", "Tokenizer.Next"}}),
			wantSatisfied: true,
			fpOrFn:        "correct positive: vulnerable html parser symbol used",
		},
		{
			name:          "GO-2025-3595 net/html / no-symbol-evidence: SBOM without symbols -> module fallback match",
			advisoryID:    "GO-2025-3595",
			route:         "no-symbol-evidence",
			imports:       netHTMLVuln,
			pkg:           noSymbols("golang.org/x/net"),
			wantSatisfied: true,
			fpOrFn:        "FN-RISK: current PR suppresses -> silent miss",
		},

		// --- GO-2026-4602 / CVE-2026-27139: stdlib os.Root escape ---
		{
			name:          "GO-2026-4602 os.Root / covered+used: escape symbol present -> match",
			advisoryID:    "GO-2026-4602",
			route:         "covered+used",
			imports:       osRootEscapeVuln,
			pkg:           pkgWithSymbols("stdlib", map[string][]string{"os": {"rootFS.ReadDir", "File.ReadDir"}}),
			wantSatisfied: true,
			fpOrFn:        "correct positive: vulnerable os symbol used",
		},
		{
			name:          "GO-2026-4602 os.Root / covered+not-used: uses os but not escape symbols -> no match",
			advisoryID:    "GO-2026-4602",
			route:         "covered+not-used",
			imports:       osRootEscapeVuln,
			pkg:           pkgWithSymbols("stdlib", map[string][]string{"os": {"Open", "Create", "Getenv"}}),
			wantSatisfied: false,
			fpOrFn:        "FP correctly avoided: os used but not the escape path",
		},
		{
			name:          "GO-2026-4602 os.Root / no-symbol-evidence: SBOM without symbols -> module fallback match",
			advisoryID:    "GO-2026-4602",
			route:         "no-symbol-evidence",
			imports:       osRootEscapeVuln,
			pkg:           noSymbols("stdlib"),
			wantSatisfied: true,
			fpOrFn:        "FN-RISK: stdlib, affects nearly every older-toolchain binary; current PR suppresses",
		},

		// --- GO-2022-0969 / CVE-2022-27664: stdlib net/http server DoS ---
		{
			name:          "GO-2022-0969 net/http-DoS / covered+used: server symbol present -> match",
			advisoryID:    "GO-2022-0969",
			route:         "covered+used",
			imports:       httpServerDoSVuln,
			pkg:           pkgWithSymbols("stdlib", map[string][]string{"net/http": {"ListenAndServe", "http2Server.ServeConn"}}),
			wantSatisfied: true,
			fpOrFn:        "correct positive: server entrypoint used",
		},
		{
			name:          "GO-2022-0969 net/http-DoS / covered+not-used: client-only net/http symbols -> no match",
			advisoryID:    "GO-2022-0969",
			route:         "covered+not-used",
			imports:       httpServerDoSVuln,
			pkg:           pkgWithSymbols("stdlib", map[string][]string{"net/http": {"Get", "NewRequest", "Client.Do", "Transport.RoundTrip"}}),
			wantSatisfied: false,
			fpOrFn:        "FP correctly avoided: only http client symbols used",
		},
		{
			name:          "GO-2022-0969 net/http-DoS / no-symbol-evidence: SBOM without symbols -> module fallback match",
			advisoryID:    "GO-2022-0969",
			route:         "no-symbol-evidence",
			imports:       httpServerDoSVuln,
			pkg:           noSymbols("stdlib"),
			wantSatisfied: true,
			fpOrFn:        "FN-RISK: current PR suppresses -> silent miss",
		},

		// --- module-level sanity: advisory carries NO imports; symbols are irrelevant, always match ---
		{
			name:          "module-level advisory / no imports + symbols present -> always match",
			advisoryID:    "module-level",
			route:         "no-imports",
			imports:       nil,
			pkg:           pkgWithSymbols("golang.org/x/crypto", map[string][]string{"golang.org/x/crypto/ssh": {"Dial"}}),
			wantSatisfied: true,
			fpOrFn:        "unaffected: pure module-level advisory",
		},
		{
			name:          "module-level advisory / no imports + no symbols -> always match",
			advisoryID:    "module-level",
			route:         "no-imports",
			imports:       nil,
			pkg:           noSymbols("golang.org/x/crypto"),
			wantSatisfied: true,
			fpOrFn:        "unaffected: pure module-level advisory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.imports).Satisfied(tt.pkg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSatisfied, got,
				"advisory=%s route=%s (%s)", tt.advisoryID, tt.route, tt.fpOrFn)
		})
	}
}
