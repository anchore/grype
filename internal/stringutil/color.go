package stringutil

import "fmt"

const (
	DefaultColor Color = iota + 30
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

type Color uint8

// TODO: not cross platform (windows...)
func (c Color) Format(s string) string {
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", c, s)
}
