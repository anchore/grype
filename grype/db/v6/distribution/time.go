package distribution

import (
	"fmt"
	"time"
)

type Time struct {
	time.Time
}

func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.Time.UTC().Round(time.Second).Format(time.RFC3339) + `"`), nil
}

func (t *Time) UnmarshalJSON(data []byte) error {
	str := string(data)
	if len(str) < 2 || str[0] != '"' || str[len(str)-1] != '"' {
		return fmt.Errorf("invalid time format")
	}
	str = str[1 : len(str)-1]

	parsedTime, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return err
	}

	t.Time = parsedTime
	return nil
}
