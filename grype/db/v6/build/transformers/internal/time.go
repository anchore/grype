package internal

import (
	"strings"
	"time"

	"github.com/araddon/dateparse"

	"github.com/anchore/grype/internal/log"
)

func ParseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return &t
	}

	// check if the timezone information is missing and append UTC if needed
	if !strings.Contains(s, "Z") && !strings.Contains(s, "+") && !strings.Contains(s, "-") {
		s += "Z"
		t, err = time.Parse(time.RFC3339, s)
		if err == nil {
			t = t.UTC()
			return &t
		}
	}

	// handle formats with milliseconds but no timezone
	formats := []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05.000Z",
	}

	for _, format := range formats {
		t, err = time.Parse(format, s)
		if err == nil {
			t = t.UTC()
			return &t
		}
	}

	// handle a wide variety of other formats
	t, err = dateparse.ParseAny(s)
	if err == nil {
		t = t.UTC()
		return &t
	}

	log.WithFields("time", s).Warnf("could not parse time: %v", err)
	return nil
}
