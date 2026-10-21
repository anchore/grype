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

func TestCheckDistroEOL_SupportEndFallback(t *testing.T) {
	past := time.Now().AddDate(-1, 0, 0)
	future := time.Now().AddDate(1, 0, 0)
	providerDate := time.Now().AddDate(-2, 0, 0)

	tests := []struct {
		name          string
		provider      vulnerability.Provider
		supportEnd    *time.Time
		expectEOL     bool
		expectEOLDate *time.Time
	}{
		{
			name:          "past SUPPORT_END is used when the provider has no data",
			provider:      newMockEOLProvider(nil, nil),
			supportEnd:    &past,
			expectEOL:     true,
			expectEOLDate: &past,
		},
		{
			name:          "future SUPPORT_END is reported but not EOL",
			provider:      newMockEOLProvider(nil, nil),
			supportEnd:    &future,
			expectEOL:     false,
			expectEOLDate: &future,
		},
		{
			name:          "SUPPORT_END is used when the provider cannot check EOL",
			provider:      mock.VulnerabilityProvider(),
			supportEnd:    &past,
			expectEOL:     true,
			expectEOLDate: &past,
		},
		{
			name:          "provider data takes precedence over SUPPORT_END",
			provider:      newMockEOLProvider(&providerDate, nil),
			supportEnd:    &future,
			expectEOL:     true,
			expectEOLDate: &providerDate,
		},
		{
			name:          "no provider data and no SUPPORT_END",
			provider:      newMockEOLProvider(nil, nil),
			supportEnd:    nil,
			expectEOL:     false,
			expectEOLDate: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := distro.New(distro.Fedora, "38", "")
			d.SupportEnd = tt.supportEnd

			status := CheckDistroEOL(tt.provider, d)

			assert.Equal(t, tt.expectEOL, status.IsEOL)
			assert.Equal(t, tt.expectEOLDate, status.EOLDate)
		})
	}
}
