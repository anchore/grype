package version

import "strings"

const (
	UnknownFormat Format = iota
	SemanticFormat
	DpkgFormat
)

type Format int

var formatStr = []string{
	"UnknownFormat",
	"Semantic",
	"Dpkg",
}

var Formats = []Format{
	SemanticFormat,
	DpkgFormat,
}

func ParseFormat(userStr string) Format {
	switch strings.ToLower(userStr) {
	case strings.ToLower(SemanticFormat.String()):
		return SemanticFormat
	case strings.ToLower(DpkgFormat.String()):
		return DpkgFormat
	}
	return UnknownFormat
}

func (f Format) String() string {
	if int(f) >= len(formatStr) || f < 0 {
		return formatStr[0]
	}

	return formatStr[f]
}
