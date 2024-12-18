package dbsearch

import (
	"fmt"

	v6 "github.com/anchore/grype/grype/db/v6"
)

type CPE v6.Cpe

func (c *CPE) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", c.String())), nil
}

func (c *CPE) String() string {
	if c == nil {
		return ""
	}
	return v6.Cpe(*c).String()
}
