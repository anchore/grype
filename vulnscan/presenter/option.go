package presenter

import "strings"

const (
	UnknownPresenter Option = iota
	JSONPresenter
)

var optionStr = []string{
	"UnknownPresenter",
	"json",
}

var Options = []Option{
	JSONPresenter,
}

type Option int

func ParseOption(userStr string) Option {
	switch strings.ToLower(userStr) {
	case strings.ToLower(JSONPresenter.String()):
		return JSONPresenter
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
