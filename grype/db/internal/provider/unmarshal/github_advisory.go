package unmarshal

import (
	"io"
)

type GitHubAdvisory struct {
	Advisory struct {
		Classification string
		CVE            []string `json:"CVE"`
		CVSS           *struct {
			BaseMetrics struct {
				BaseScore           float64 `json:"base_score"`
				BaseSeverity        string  `json:"base_severity"`
				ExploitabilityScore float64 `json:"exploitability_score"`
				ImpactScore         float64 `json:"impact_score"`
			} `json:"base_metrics"`
			Status       string `json:"status"`
			VectorString string `json:"vector_string"`
			Version      string `json:"version"`
		} `json:"CVSS"`
		FixedIn  []GithubFixedIn `json:"FixedIn"`
		Metadata struct {
			CVE []string `json:"CVE"`
		} `json:"Metadata"`
		Severity  string `json:"Severity"`
		Summary   string `json:"Summary"`
		GhsaID    string `json:"ghsaId"`
		Namespace string `json:"namespace"`
		URL       string `json:"url"`
		Published string `json:"published"`
		Updated   string `json:"updated"`
		Withdrawn string `json:"withdrawn"`
	} `json:"Advisory"`
}

func (g GitHubAdvisory) IsEmpty() bool {
	return g.Advisory.GhsaID == ""
}

func GitHubAdvisoryEntries(reader io.Reader) ([]GitHubAdvisory, error) {
	return unmarshalSingleOrMulti[GitHubAdvisory](reader)
}

type GithubFixedIn struct {
	Ecosystem  string `json:"ecosystem"`
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Range      string `json:"range"`
	Available  struct {
		Date string `json:"date,omitempty"`
		Kind string `json:"kind,omitempty"`
	} `json:"available,omitempty"`
}
