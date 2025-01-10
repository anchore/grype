package db

import (
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/vulnerability"
)

type MockProvider = v5.MockStore

func NewMockProvider(vulnerabilities ...vulnerability.Vulnerability) *MockProvider {
	return &MockProvider{
		Vulnerabilities: vulnerabilities,
	}
}
