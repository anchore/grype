package presenter

import "strings"

const (
	UnknownPresenter Option = iota
	JSONPresenter
	TablePresenter
)

var optionStr = []string{
	"UnknownPresenter",
	"json",
	"table",
}

var Options = []Option{
	JSONPresenter,
	TablePresenter,
}

type Option int

func ParseOption(userStr string) Option {
	switch strings.ToLower(userStr) {
	case strings.ToLower(JSONPresenter.String()):
		return JSONPresenter
	case strings.ToLower(TablePresenter.String()):
		return TablePresenter
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
