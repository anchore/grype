package stringutil

type StringSet map[string]struct{}

func NewStringSet() StringSet {
	return make(StringSet)
}

func NewStringSetFromSlice(start []string) StringSet {
	ret := make(StringSet)
	for _, s := range start {
		ret.Add(s)
	}
	return ret
}

func (s StringSet) Add(i string) {
	s[i] = struct{}{}
}

func (s StringSet) Remove(i string) {
	delete(s, i)
}

func (s StringSet) Contains(i string) bool {
	_, ok := s[i]
	return ok
}

func (s StringSet) ToSlice() []string {
	ret := make([]string, len(s))
	idx := 0
	for v := range s {
		ret[idx] = v
		idx++
	}
	return ret
}
