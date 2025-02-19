package schemaver

import "fmt"

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
		return "", fmt.Errorf("invalid schema version format: %s", s)
	}
	// check that all parts are integers
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return "", fmt.Errorf("invalid schema version format: %s", s)
		}
	}
	return SchemaVer(s), nil
}

func (s SchemaVer) String() string {
	return fmt.Sprintf("%d.%d.%d", s.Model, s.Revision, s.Addition)
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

func (s SchemaVer) GreaterThanEqual(other SchemaVer) bool {
	return !s.LessThan(other)
}

func (s SchemaVer) LessThan(other SchemaVer) bool {
	return s.compare(other) < 0
}

func (s SchemaVer) GreaterOrEqualTo(other SchemaVer) bool {
	return s.compare(other) >= 0
}

func (s SchemaVer) compare(other SchemaVer) int {
	parts := strings.Split(string(s), ".")
	otherParts := strings.Split(string(other), ".")

	for i := 0; i < 3; i++ {
		v1 := 0
		if i < len(parts) {
			v1, _ = strconv.Atoi(parts[i])
		}

		v2 := 0
		if i < len(otherParts) {
			v2, _ = strconv.Atoi(otherParts[i])
		}

		if v1 < v2 {
			return -1
		} else if v1 > v2 {
			return 1
		}
	}

	return 0
}
