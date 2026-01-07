package unmarshal

import "io"

type EPSS struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

func (o EPSS) IsEmpty() bool {
	return o.CVE == ""
}

func EPSSEntries(reader io.Reader) ([]EPSS, error) {
	return unmarshalSingleOrMulti[EPSS](reader)
}
