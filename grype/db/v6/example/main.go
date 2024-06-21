package main

import (
	"fmt"
	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"os"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	lcfg := logrus.DefaultConfig()
	lcfg.Level = logger.TraceLevel
	lgr, err := logrus.New(lcfg)

	grype.SetLogger(lgr)

	cfg := v6.StoreConfig{
		BatchSize: 100,
		DBDirPath: "/tmp",
		Overwrite: true,
	}

	s, err := v6.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create store: %w", err)
	}

	if err = populateFixture1(s); err != nil {
		return fmt.Errorf("failed to populate fixture 1: %w", err)
	}

	vulns, err := s.GetVulnerability("CVE-2024-12343", true)
	if err != nil {
		return fmt.Errorf("failed to get vuln (1): %w", err)
	}

	fmt.Printf("vulns (2): %+v\n", len(vulns))
	for _, v := range vulns {
		fmt.Printf(" - %s\n", vulnStringer{v})
		//if v.Affecteds != nil {
		//	fmt.Printf("   Affecteds:\n")
		//	for _, s := range *v.Affecteds {
		//		fmt.Printf("   - %s\n", affectedStringer{s})
		//	}
		//}
	}

	return nil
}

//func run() error {
//	cfg := v6.StoreConfig{
//		BatchSize:  100,
//		DBFilePath: "/tmp/vuln.db",
//		Overwrite:  true,
//	}
//	s, err := v6.New(cfg)
//	if err != nil {
//		return fmt.Errorf("failed to create store: %w", err)
//	}
//
//	provider := v6.Provider{
//		ID:      0,
//		Name:    "nvd",
//		Version: "1.0",
//	}
//
//	if err := s.AddProviders(&provider); err != nil {
//		return fmt.Errorf("failed to add provider: %w", err)
//	}
//
//	err = s.AddVulnerabilities(
//		&v6.Vulnerability{
//			ProviderID: provider.ID,
//			Name:       "CVE-2021-1234",
//			Severities: &[]v6.Severity{
//				{
//					Type:     "something",
//					Score:    "2.0",
//					Source:   "nvd",
//					Priority: "something-else",
//				},
//			},
//		},
//		&v6.Vulnerability{
//			ProviderID: provider.ID,
//			Name:       "CVE-2021-5678",
//			Severities: &[]v6.Severity{
//				{
//					Type:     "something",
//					Score:    "2.0",
//					Source:   "nvd",
//					Priority: "something-else",
//				},
//			},
//		},
//	)
//	if err != nil {
//		return fmt.Errorf("failed to add vulns: %w", err)
//	}
//
//	vulns, err := s.GetVulnerability("CVE-2021-1234", true)
//	if err != nil {
//		return fmt.Errorf("failed to get vuln (1): %w", err)
//	}
//
//	fmt.Printf("vulns (2): %+v\n", len(vulns))
//	for _, v := range vulns {
//		fmt.Printf(" - %s\n", vulnStringer{v})
//	}
//
//	vulns, err = s.GetVulnerability("CVE-2021-5678", true)
//	if err != nil {
//		return fmt.Errorf("failed to get vuln (2): %w", err)
//	}
//
//	fmt.Printf("vulns (2): %+v\n", len(vulns))
//	for _, v := range vulns {
//		fmt.Printf(" - %s\n", vulnStringer{v})
//	}
//
//	return nil
//}

type vulnStringer struct {
	v6.Vulnerability
}

func (v vulnStringer) String() string {
	aff := "n/a"
	//if v.Affecteds != nil {
	//	aff = fmt.Sprintf("%d", len(*v.Affecteds))
	//}
	return fmt.Sprintf("Vulnerability[%d]{ID=%q, len(Affected)=%s, %v, %v}", v.ID, v.Name, aff, providerStringer{v.Provider}, severityStringer(v.Severities))
}

type providerStringer struct {
	*v6.Provider
}

func (v providerStringer) String() string {
	if v.Provider == nil {
		return "Provider=<nil>"
	}
	return fmt.Sprintf("Provider[%s]{Version=%q}", v.ID, v.Version)
}

func severityStringer(vs *[]v6.Severity) string {
	if vs == nil {
		return "Severities=<nil>"
	}

	stringer := func(v v6.Severity) string {
		return fmt.Sprintf("{Type=%q, Score=%q, Source=%q, Priority=%q}", v.Type, v.Score, v.Source, v.Priority)
	}

	var strs []string
	for _, v := range *vs {
		strs = append(strs, stringer(v))
	}

	return fmt.Sprintf("[]Severity{%s}", strings.Join(strs, ", "))
}

type affectedStringer struct {
	v6.Affected
}

func (v affectedStringer) String() string {
	return fmt.Sprintf("Affected[%d]{%v}", v.ID, affectedPackageStringer{v.Package})
}

type affectedPackageStringer struct {
	*v6.Package
}

func (v affectedPackageStringer) String() string {
	if v.Package == nil {
		return "Package=<nil>"
	}
	return fmt.Sprintf("Package[%d]{Ecosystem=%q, Name=%q, %v}", v.ID, v.Ecosystem, v.Name, operatingSystemStringer{v.OperatingSystem})
}

type operatingSystemStringer struct {
	*v6.OperatingSystem
}

func (v operatingSystemStringer) String() string {
	if v.OperatingSystem == nil {
		return "OperatingSystem=<nil>"
	}
	return fmt.Sprintf("OperatingSystem[%d]{Name=%q, MajorVersion=%q, MinorVersion=%q}", v.ID, v.Name, v.MajorVersion, v.MinorVersion)
}
