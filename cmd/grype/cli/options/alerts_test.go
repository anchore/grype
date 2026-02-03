package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultAlerts(t *testing.T) {
	alerts := defaultAlerts()

	// EOL distro warnings should be enabled by default
	assert.True(t, alerts.ShowEOLDistroWarnings, "ShowEOLDistroWarnings should be true by default")
}
