package common

import (
	"strings"
	"sync"
)

// TODO: move me to a common module (used in multiple repos)

const (
	SpinnerCircleOutlineSet = "◜◠◯◎◉●◉◎◯◡◞"
	SpinnerCircleSet        = "◌◯◎◉●◉◎◯"
	SpinnerDotSet           = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
	SpinnerHorizontalBarSet = "▉▊▋▌▍▎▏▎▍▌▋▊▉"
	SpinnerVerticalBarSet   = "▁▃▄▅▆▇█▇▆▅▄▃▁"
	SpinnerDoubleBarSet     = "▁▂▃▄▅▆▇█▉▊▋▌▍▎▏▏▎▍▌▋▊▉█▇▆▅▄▃▂▁"
	SpinnerArrowSet         = "←↖↑↗→↘↓↙"
)

var SpinnerCircleDotSet = []string{
	"⠈⠁",
	"⠈⠑",
	"⠈⠱",
	"⠈⡱",
	"⢀⡱",
	"⢄⡱",
	"⢄⡱",
	"⢆⡱",
	"⢎⡱",
	"⢎⡰",
	"⢎⡠",
	"⢎⡀",
	"⢎⠁",
	"⠎⠁",
	"⠊⠁",
}

type Spinner struct {
	index   int
	charset []string
	lock    sync.Mutex
}

func NewSpinner(charset string) Spinner {
	return Spinner{
		charset: strings.Split(charset, ""),
	}
}

func NewSpinnerFromSlice(charset []string) Spinner {
	return Spinner{
		charset: charset,
	}
}

func (s *Spinner) Current() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.charset[s.index]
}

func (s *Spinner) Next() string {
	s.lock.Lock()
	defer s.lock.Unlock()
	c := s.charset[s.index]
	s.index++
	if s.index >= len(s.charset) {
		s.index = 0
	}
	return c
}
