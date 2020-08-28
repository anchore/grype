package presenter

import "strings"

const (
	UnknownPresenter Option = iota
	JSONPresenter
	TablePresenter
	CycloneDxPresenter
)

var optionStr = []string{
	"UnknownPresenter",
	"json",
	"table",
	"cyclonedx",
}

var Options = []Option{
	JSONPresenter,
	TablePresenter,
	CycloneDxPresenter,
}

type Option int

func ParseOption(userStr string) Option {
	switch strings.ToLower(userStr) {
	case strings.ToLower(JSONPresenter.String()):
		return JSONPresenter
	case strings.ToLower(TablePresenter.String()):
		return TablePresenter
	case strings.ToLower(CycloneDxPresenter.String()):
		return CycloneDxPresenter
	default:
		return UnknownPresenter
	}
}

func (o Option) String() string {
	if int(o) >= len(optionStr) || o < 0 {
		return optionStr[0]
	}

	return optionStr[o]
}
