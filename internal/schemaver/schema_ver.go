package schemaver

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type SchemaVer struct {
	Model    int // breaking changes
	Revision int // potentially-breaking changes
	Addition int // additions only
}

func New(model, revision, addition int) SchemaVer {
	return SchemaVer{
		Model:    model,
		Revision: revision,
		Addition: addition,
	}
}

func Parse(s string) (SchemaVer, error) {
	// must provide model.revision.addition
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return SchemaVer{}, fmt.Errorf("invalid schema version format: %s", s)
	}
	// check that all parts are integers
	var values [3]int
	for i, part := range parts {
		if i == 0 {
			part = strings.TrimPrefix(part, "v")
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 {
			return SchemaVer{}, fmt.Errorf("invalid schema version format: %s", s)
		}
		values[i] = v
	}
	if values[0] < 1 {
		return SchemaVer{}, fmt.Errorf("model value must be greater than 0: %s", s)
	}
	return New(values[0], values[1], values[2]), nil
}

func (s SchemaVer) Valid() bool {
	return s.Model > 0 && s.Revision >= 0 && s.Addition >= 0
}

func (s SchemaVer) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

func (s *SchemaVer) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("failed to unmarshal schema version as string: %w", err)
	}

	parsed, err := Parse(str)
	if err != nil {
		return fmt.Errorf("failed to parse schema version: %w", err)
	}
	*s = parsed
	return nil
}

func (s SchemaVer) String() string {
	return fmt.Sprintf("v%d.%d.%d", s.Model, s.Revision, s.Addition)
}

func (s SchemaVer) LessThan(other SchemaVer) bool {
	if s.Model != other.Model {
		return s.Model < other.Model
	}

	if s.Revision != other.Revision {
		return s.Revision < other.Revision
	}

	return s.Addition < other.Addition
}

func (s SchemaVer) GreaterOrEqualTo(other SchemaVer) bool {
	return !s.LessThan(other)
}
