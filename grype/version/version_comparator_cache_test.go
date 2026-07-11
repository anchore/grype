package version

import "testing"

func TestGetComparatorDoesNotCacheParseFailure(t *testing.T) {
	// "3.e" is not a valid semantic version; the comparator fails to build.
	// It must not be cached, otherwise a later lookup returns it with a nil
	// error and then panics (nil *hashiVer.Version) when used.
	v := New("3.e", SemanticFormat)
	other := New("1.0", SemanticFormat)

	if _, err := v.Is(LT, other); err == nil {
		t.Fatal("expected an error comparing an unparseable version, got nil")
	}
	// second call must behave the same (surface the error), not panic.
	if _, err := v.Is(LT, other); err == nil {
		t.Fatal("expected an error on the repeated comparison, got nil (broken comparator was cached)")
	}
}
