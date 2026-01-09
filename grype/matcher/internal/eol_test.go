package internal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
)

// mockEOLProvider wraps mock.VulnerabilityProvider and adds EOLChecker support
type mockEOLProvider struct {
	vulnerability.Provider
	eolDate  *time.Time
	eoasDate *time.Time
	err      error
}

func (m *mockEOLProvider) GetOperatingSystemEOL(d *distro.Distro) (eolDate, eoasDate *time.Time, err error) {
	return m.eolDate, m.eoasDate, m.err
}

func newMockEOLProvider(eolDate, eoasDate *time.Time) *mockEOLProvider {
	return &mockEOLProvider{
		Provider: mock.VulnerabilityProvider(),
		eolDate:  eolDate,
		eoasDate: eoasDate,
	}
}

func TestCheckDistroEOL_NilDistro(t *testing.T) {
	provider := newMockEOLProvider(nil, nil)
	status := CheckDistroEOL(provider, nil)

	assert.False(t, status.IsEOL)
	assert.False(t, status.IsEOAS)
	assert.Nil(t, status.EOLDate)
	assert.Nil(t, status.EOASDate)
}

func TestCheckDistroEOL_ProviderDoesNotSupportEOL(t *testing.T) {
	// use base mock provider without EOLChecker
	provider := mock.VulnerabilityProvider()
	d := distro.New(distro.Ubuntu, "18.04", "")

	status := CheckDistroEOL(provider, d)

	assert.False(t, status.IsEOL)
	assert.False(t, status.IsEOAS)
	assert.Nil(t, status.EOLDate)
	assert.Nil(t, status.EOASDate)
}

func TestCheckDistroEOL_PastEOLDate(t *testing.T) {
	pastDate := time.Now().AddDate(-1, 0, 0) // 1 year ago
	provider := newMockEOLProvider(&pastDate, nil)
	d := distro.New(distro.Ubuntu, "18.04", "")

	status := CheckDistroEOL(provider, d)

	assert.True(t, status.IsEOL)
	assert.False(t, status.IsEOAS)
	assert.NotNil(t, status.EOLDate)
	assert.Equal(t, pastDate, *status.EOLDate)
}

func TestCheckDistroEOL_FutureEOLDate(t *testing.T) {
	futureDate := time.Now().AddDate(1, 0, 0) // 1 year from now
	provider := newMockEOLProvider(&futureDate, nil)
	d := distro.New(distro.Ubuntu, "22.04", "")

	status := CheckDistroEOL(provider, d)

	assert.False(t, status.IsEOL)
	assert.False(t, status.IsEOAS)
	assert.NotNil(t, status.EOLDate)
	assert.Equal(t, futureDate, *status.EOLDate)
}

func TestCheckDistroEOL_PastEOASDate(t *testing.T) {
	pastEOAS := time.Now().AddDate(-1, 0, 0) // 1 year ago
	futureEOL := time.Now().AddDate(1, 0, 0) // 1 year from now
	provider := newMockEOLProvider(&futureEOL, &pastEOAS)
	d := distro.New(distro.Ubuntu, "20.04", "")

	status := CheckDistroEOL(provider, d)

	assert.False(t, status.IsEOL)
	assert.True(t, status.IsEOAS)
	assert.NotNil(t, status.EOLDate)
	assert.NotNil(t, status.EOASDate)
}

func TestCheckDistroEOL_NoEOLData(t *testing.T) {
	provider := newMockEOLProvider(nil, nil)
	d := distro.New(distro.Ubuntu, "24.04", "")

	status := CheckDistroEOL(provider, d)

	assert.False(t, status.IsEOL)
	assert.False(t, status.IsEOAS)
	assert.Nil(t, status.EOLDate)
	assert.Nil(t, status.EOASDate)
}

func TestIsDistroEOL(t *testing.T) {
	tests := []struct {
		name     string
		eolDate  *time.Time
		expected bool
	}{
		{
			name:     "past EOL date returns true",
			eolDate:  ptrTime(time.Now().AddDate(-1, 0, 0)),
			expected: true,
		},
		{
			name:     "future EOL date returns false",
			eolDate:  ptrTime(time.Now().AddDate(1, 0, 0)),
			expected: false,
		},
		{
			name:     "nil EOL date returns false",
			eolDate:  nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newMockEOLProvider(tt.eolDate, nil)
			d := distro.New(distro.Ubuntu, "18.04", "")

			result := IsDistroEOL(provider, d)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
