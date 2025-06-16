package internal

import (
	"reflect"
	"testing"
)

func TestNewOrderedSet(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected []string
	}{
		{
			name:     "empty set",
			items:    []string{},
			expected: []string{},
		},
		{
			name:     "single item",
			items:    []string{"a"},
			expected: []string{"a"},
		},
		{
			name:     "multiple items",
			items:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "duplicate items",
			items:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewOrderedSet(tt.items...)
			result := set.ToSlice()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("NewOrderedSet() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestOrderedSet_Add(t *testing.T) {
	tests := []struct {
		name          string
		initial       []string
		addItems      []string
		expectedSize  int
		expectedAdded int
		expectedItems []string
	}{
		{
			name:          "add to empty set",
			initial:       []string{},
			addItems:      []string{"a", "b"},
			expectedSize:  2,
			expectedAdded: 2,
			expectedItems: []string{"a", "b"},
		},
		{
			name:          "add new items",
			initial:       []string{"a"},
			addItems:      []string{"b", "c"},
			expectedSize:  3,
			expectedAdded: 2,
			expectedItems: []string{"a", "b", "c"},
		},
		{
			name:          "add duplicate items",
			initial:       []string{"a", "b"},
			addItems:      []string{"b", "c"},
			expectedSize:  3,
			expectedAdded: 1,
			expectedItems: []string{"a", "b", "c"},
		},
		{
			name:          "add all duplicates",
			initial:       []string{"a", "b", "c"},
			addItems:      []string{"a", "b", "c"},
			expectedSize:  3,
			expectedAdded: 0,
			expectedItems: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewOrderedSet(tt.initial...)
			added := set.Add(tt.addItems...)

			if added != tt.expectedAdded {
				t.Errorf("Add() returned %d, expected %d", added, tt.expectedAdded)
			}

			if set.Size() != tt.expectedSize {
				t.Errorf("Size() = %d, expected %d", set.Size(), tt.expectedSize)
			}

			result := set.ToSlice()
			if !reflect.DeepEqual(result, tt.expectedItems) {
				t.Errorf("ToSlice() = %v, expected %v", result, tt.expectedItems)
			}
		})
	}
}

func TestOrderedSet_Add_NilSet(t *testing.T) {
	var set *OrderedSet[string]

	// This should panic since we can't modify a nil pointer
	defer func() {
		if r := recover(); r == nil {
			t.Error("Add() on nil set should panic")
		}
	}()

	set.Add("a", "b")
}

func TestOrderedSet_Delete(t *testing.T) {
	tests := []struct {
		name            string
		initial         []string
		deleteItems     []string
		expectedSize    int
		expectedRemoved int
		expectedItems   []string
	}{
		{
			name:            "delete from empty set",
			initial:         []string{},
			deleteItems:     []string{"a"},
			expectedSize:    0,
			expectedRemoved: 0,
			expectedItems:   []string{},
		},
		{
			name:            "delete existing items",
			initial:         []string{"a", "b", "c"},
			deleteItems:     []string{"b"},
			expectedSize:    2,
			expectedRemoved: 1,
			expectedItems:   []string{"a", "c"},
		},
		{
			name:            "delete multiple items",
			initial:         []string{"a", "b", "c", "d"},
			deleteItems:     []string{"b", "d"},
			expectedSize:    2,
			expectedRemoved: 2,
			expectedItems:   []string{"a", "c"},
		},
		{
			name:            "delete non-existing items",
			initial:         []string{"a", "b", "c"},
			deleteItems:     []string{"x", "y"},
			expectedSize:    3,
			expectedRemoved: 0,
			expectedItems:   []string{"a", "b", "c"},
		},
		{
			name:            "delete mix of existing and non-existing",
			initial:         []string{"a", "b", "c"},
			deleteItems:     []string{"b", "x", "c"},
			expectedSize:    1,
			expectedRemoved: 2,
			expectedItems:   []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewOrderedSet(tt.initial...)
			removed := set.Delete(tt.deleteItems...)

			if removed != tt.expectedRemoved {
				t.Errorf("Delete() returned %d, expected %d", removed, tt.expectedRemoved)
			}

			if set.Size() != tt.expectedSize {
				t.Errorf("Size() = %d, expected %d", set.Size(), tt.expectedSize)
			}

			result := set.ToSlice()
			if !reflect.DeepEqual(result, tt.expectedItems) {
				t.Errorf("ToSlice() = %v, expected %v", result, tt.expectedItems)
			}
		})
	}
}

func TestOrderedSet_Delete_NilSet(t *testing.T) {
	var set *OrderedSet[string]
	removed := set.Delete("a")

	if removed != 0 {
		t.Errorf("Delete() on nil set returned %d, expected 0", removed)
	}
}

func TestOrderedSet_Contains(t *testing.T) {
	set := NewOrderedSet("a", "b", "c")

	tests := []struct {
		item     string
		expected bool
	}{
		{"a", true},
		{"b", true},
		{"c", true},
		{"d", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.item, func(t *testing.T) {
			result := set.Contains(tt.item)
			if result != tt.expected {
				t.Errorf("Contains(%q) = %v, expected %v", tt.item, result, tt.expected)
			}
		})
	}
}

func TestOrderedSet_Contains_NilSet(t *testing.T) {
	var set *OrderedSet[string]
	result := set.Contains("a")

	if result != false {
		t.Errorf("Contains() on nil set returned %v, expected false", result)
	}
}

func TestOrderedSet_Size(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected int
	}{
		{"empty set", []string{}, 0},
		{"single item", []string{"a"}, 1},
		{"multiple items", []string{"a", "b", "c"}, 3},
		{"duplicates", []string{"a", "b", "a", "c"}, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewOrderedSet(tt.items...)
			result := set.Size()
			if result != tt.expected {
				t.Errorf("Size() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestOrderedSet_Size_NilSet(t *testing.T) {
	var set *OrderedSet[string]
	result := set.Size()

	if result != 0 {
		t.Errorf("Size() on nil set returned %d, expected 0", result)
	}
}

func TestOrderedSet_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected bool
	}{
		{"empty set", []string{}, true},
		{"non-empty set", []string{"a"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewOrderedSet(tt.items...)
			result := set.IsEmpty()
			if result != tt.expected {
				t.Errorf("IsEmpty() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestOrderedSet_IsEmpty_NilSet(t *testing.T) {
	var set *OrderedSet[string]
	result := set.IsEmpty()

	if result != true {
		t.Errorf("IsEmpty() on nil set returned %v, expected true", result)
	}
}

func TestOrderedSet_ToSlice(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected []string
	}{
		{"empty set", []string{}, []string{}},
		{"single item", []string{"a"}, []string{"a"}},
		{"multiple items", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"maintains order", []string{"c", "a", "b"}, []string{"c", "a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewOrderedSet(tt.items...)
			result := set.ToSlice()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ToSlice() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestOrderedSet_ToSlice_NilSet(t *testing.T) {
	var set *OrderedSet[string]
	result := set.ToSlice()

	if result != nil {
		t.Errorf("ToSlice() on nil set returned %v, expected nil", result)
	}
}

func TestOrderedSet_ToSlice_Copy(t *testing.T) {
	set := NewOrderedSet("a", "b", "c")
	slice1 := set.ToSlice()
	slice2 := set.ToSlice()

	// Modify one slice
	slice1[0] = "modified"

	// Verify the other slice is unaffected
	if slice2[0] != "a" {
		t.Errorf("ToSlice() did not return a copy, slice2[0] = %q, expected 'a'", slice2[0])
	}

	// Verify the set is unaffected
	if !set.Contains("a") {
		t.Error("Original set was modified when slice was changed")
	}
}

func TestOrderedSet_Clear(t *testing.T) {
	set := NewOrderedSet("a", "b", "c")

	if set.Size() != 3 {
		t.Errorf("Initial size = %d, expected 3", set.Size())
	}

	set.Clear()

	if set.Size() != 0 {
		t.Errorf("Size after Clear() = %d, expected 0", set.Size())
	}

	if !set.IsEmpty() {
		t.Error("IsEmpty() after Clear() = false, expected true")
	}

	if set.Contains("a") {
		t.Error("Contains('a') after Clear() = true, expected false")
	}
}

func TestOrderedSet_Clear_NilSet(t *testing.T) {
	var set *OrderedSet[string]
	set.Clear() // Should not panic
}

func TestOrderedSet_String(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected string
	}{
		{"empty set", []string{}, "OrderedSet[]"},
		{"single item", []string{"a"}, "OrderedSet[a]"},
		{"multiple items", []string{"a", "b", "c"}, "OrderedSet[a b c]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewOrderedSet(tt.items...)
			result := set.String()
			if result != tt.expected {
				t.Errorf("String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestOrderedSet_String_NilSet(t *testing.T) {
	var set *OrderedSet[string]
	result := set.String()
	expected := "OrderedSet{}"

	if result != expected {
		t.Errorf("String() on nil set = %q, expected %q", result, expected)
	}
}

func TestOrderedSet_IntegerType(t *testing.T) {
	set := NewOrderedSet(3, 1, 4, 1, 5, 9, 2, 6, 5)
	expected := []int{3, 1, 4, 5, 9, 2, 6}

	result := set.ToSlice()
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Integer OrderedSet = %v, expected %v", result, expected)
	}

	if set.Size() != 7 {
		t.Errorf("Size() = %d, expected 7", set.Size())
	}
}

func TestOrderedSet_OrderPreservation(t *testing.T) {
	set := NewOrderedSet[string]()

	// Add items in specific order
	set.Add("third")
	set.Add("first")
	set.Add("second")
	set.Add("first") // duplicate, should not change order

	expected := []string{"third", "first", "second"}
	result := set.ToSlice()

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Order not preserved: got %v, expected %v", result, expected)
	}
}
