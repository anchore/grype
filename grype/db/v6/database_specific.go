package v6

type DatabaseSpecificNvd struct {
	VulnStatus            string `json:"VulnStatus"`
	CisaExploitAdd        string `json:"CisaExploitAdd"`
	CisaActionDue         string `json:"CisaActionDue"`
	CisaRequiredAction    string `json:"CisaRequiredAction"`
	CisaVulnerabilityName string `json:"CisaVulnerabilityName"`
}
