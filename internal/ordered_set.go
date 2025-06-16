package internal

import "fmt"

// OrderedSet maintains insertion order while ensuring uniqueness
type OrderedSet[T comparable] struct {
	items   []T
	itemMap map[T]bool
}

// NewOrderedSet creates a new ordered set with optional initial elements
func NewOrderedSet[T comparable](items ...T) *OrderedSet[T] {
	s := &OrderedSet[T]{
		items:   make([]T, 0),
		itemMap: make(map[T]bool),
	}
	s.Add(items...)
	return s
}

// Add inserts one or more elements into the set. Returns the number of elements actually added
func (s *OrderedSet[T]) Add(items ...T) int {
	if s == nil {
		*s = *NewOrderedSet[T]()
	}
	added := 0
	for _, item := range items {
		if !s.itemMap[item] {
			s.items = append(s.items, item)
			s.itemMap[item] = true
			added++
		}
	}
	return added
}

// Delete removes one or more elements from the set. Returns the number of elements actually removed
func (s *OrderedSet[T]) Delete(items ...T) int {
	if s == nil {
		return 0
	}
	removed := 0
	for _, item := range items {
		if s.itemMap[item] {
			// Find and remove from slice
			for i, v := range s.items {
				if v == item {
					s.items = append(s.items[:i], s.items[i+1:]...)
					break
				}
			}
			delete(s.itemMap, item)
			removed++
		}
	}
	return removed
}

// Contains checks if an element exists in the set
func (s *OrderedSet[T]) Contains(item T) bool {
	if s == nil {
		return false
	}
	return s.itemMap[item]
}

// Size returns the number of elements in the set
func (s *OrderedSet[T]) Size() int {
	if s == nil {
		return 0
	}
	return len(s.items)
}

// IsEmpty returns true if the set is empty
func (s *OrderedSet[T]) IsEmpty() bool {
	return s == nil || len(s.items) == 0
}

// ToSlice returns a slice of all elements in insertion order
func (s *OrderedSet[T]) ToSlice() []T {
	if s == nil {
		return nil
	}
	result := make([]T, len(s.items))
	copy(result, s.items)
	return result
}

// Clear removes all elements from the set
func (s *OrderedSet[T]) Clear() {
	if s == nil {
		return
	}
	s.items = s.items[:0]
	s.itemMap = make(map[T]bool)
}

// String returns a string representation of the set
func (s *OrderedSet[T]) String() string {
	if s == nil {
		return "OrderedSet{}"
	}
	return fmt.Sprintf("OrderedSet%v", s.items)
}
