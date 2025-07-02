package version

import (
	"sort"
)

type Set struct {
	versions map[string]*Version
	getKey   func(v *Version) string
}

func NewSet(ignoreFormat bool, vs ...*Version) *Set {
	var getKey func(v *Version) string
	if ignoreFormat {
		getKey = func(v *Version) string {
			if v == nil {
				return ""
			}
			return v.Raw
		}
	} else {
		getKey = func(v *Version) string {
			if v == nil {
				return ""
			}
			return v.Raw + ":" + v.Format.String()
		}
	}
	s := &Set{
		versions: make(map[string]*Version),
		getKey:   getKey,
	}
	s.Add(vs...)
	return s
}

func (s *Set) Add(vs ...*Version) {
	if s.versions == nil {
		s.versions = make(map[string]*Version)
	}

	for _, v := range vs {
		if v == nil {
			continue
		}
		key := s.getKey(v)
		s.versions[key] = v
	}
}

func (s *Set) Remove(vs ...*Version) {
	if s.versions == nil {
		return
	}

	for _, v := range vs {
		if v == nil {
			continue
		}
		key := s.getKey(v)
		delete(s.versions, key)
	}
}

func (s *Set) Contains(v *Version) bool {
	if v == nil || s.versions == nil {
		return false
	}

	key := s.getKey(v)
	_, exists := s.versions[key]
	return exists
}

func (s *Set) Values() []*Version {
	if len(s.versions) == 0 {
		return nil
	}

	out := make([]*Version, 0, len(s.versions))
	for _, v := range s.versions {
		out = append(out, v)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i] == nil && out[j] == nil {
			return false
		}
		if out[i] == nil {
			return true
		}
		if out[j] == nil {
			return false
		}
		cmp, err := out[i].Compare(out[j])
		if err != nil {
			return false // if we can't compare, don't change the order
		}
		return cmp < 0
	})

	return out
}

func (s *Set) Size() int {
	if s.versions == nil {
		return 0
	}
	return len(s.versions)
}

func (s *Set) Clear() {
	if s.versions != nil {
		s.versions = make(map[string]*Version)
	}
}
