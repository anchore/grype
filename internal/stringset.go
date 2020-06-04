package internal

type Set map[string]struct{}

func NewStringSet() Set {
	return make(Set)
}

func (s Set) Add(i string) {
	s[i] = struct{}{}
}

func (s Set) Remove(i string) {
	delete(s, i)
}

func (s Set) Contains(i string) bool {
	_, ok := s[i]
	return ok
}
