package v6

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockCachableID struct {
	key   string
	table string
	id    ID
}

func (m *mockCachableID) cacheKey() string  { return m.key }
func (m *mockCachableID) tableName() string { return m.table }
func (m *mockCachableID) rowID() ID         { return m.id }
func (m *mockCachableID) setRowID(id ID)    { m.id = id }

type mockCachableString struct {
	key   string
	table string
	id    string
}

func (m *mockCachableString) cacheKey() string   { return m.key }
func (m *mockCachableString) tableName() string  { return m.table }
func (m *mockCachableString) rowID() string      { return m.id }
func (m *mockCachableString) setRowID(id string) { m.id = id }

func newTestCachableString(key, table, id string) *mockCachableString {
	return &mockCachableString{key: key, table: table, id: id}
}

func newTestCachableID(key, table string, id ID) *mockCachableID {
	return &mockCachableID{key: key, table: table, id: id}
}

func TestCache_GetString_Found(t *testing.T) {
	c := newCache()
	item := newTestCachableString("test-key", "test-table", "test-id")

	c.setStringEntry("test-id", item)

	str, found := c.getString(item)
	require.True(t, found)
	require.Equal(t, "test-id", str)
}

func TestCache_GetString_NotFound(t *testing.T) {
	c := newCache()
	item := newTestCachableString("missing-key", "test-table", "")

	str, found := c.getString(item)
	require.False(t, found)
	require.Empty(t, str)
}

func TestCache_Set_ID(t *testing.T) {
	c := newCache()
	item := newTestCachableID("test-key", "test-table", 123)

	c.set(item)

	id, found := c.getID(item)
	require.True(t, found)
	require.Equal(t, ID(123), id)
}

func TestCache_Set_String(t *testing.T) {
	c := newCache()
	item := newTestCachableString("test-key", "test-table", "test-id")

	c.set(item)

	str, found := c.getString(item)
	require.True(t, found)
	require.Equal(t, "test-id", str)
}

func TestCache_Set_Panic(t *testing.T) {
	c := newCache()
	invalidItem := struct{ cachable }{}

	require.PanicsWithValue(t, "unsupported cacheable type", func() {
		c.set(invalidItem)
	})
}

func TestCache_SetStringEntry_New(t *testing.T) {
	c := newCache()
	item := newTestCachableString("test-key", "test-table", "")

	c.setStringEntry("new-id", item)

	str, found := c.getString(item)
	require.True(t, found)
	require.Equal(t, "new-id", str)
}

func TestCache_SetStringEntry_Update(t *testing.T) {
	c := newCache()
	item := newTestCachableString("test-key", "test-table", "old-id")

	c.setStringEntry("old-id", item)
	c.setStringEntry("new-id", item)

	str, found := c.getString(item)
	require.True(t, found)
	require.Equal(t, "new-id", str)
}

func TestCache_SetIDEntry_New(t *testing.T) {
	c := newCache()
	item := newTestCachableID("test-key", "test-table", 0)

	c.setIDEntry(123, item)

	id, found := c.getID(item)
	require.True(t, found)
	require.Equal(t, ID(123), id)
}

func TestCache_SetIDEntry_Update(t *testing.T) {
	c := newCache()
	item := newTestCachableID("test-key", "test-table", 123)

	c.setIDEntry(123, item)
	c.setIDEntry(456, item)

	id, found := c.getID(item)
	require.True(t, found)
	require.Equal(t, ID(456), id)
}

func TestWithCacheContext(t *testing.T) {
	c := newCache()
	ctx := withCacheContext(context.Background(), c)

	cache, ok := cacheFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, c, cache)
}

func TestCacheFromContext_NotFound(t *testing.T) {
	cache, ok := cacheFromContext(context.Background())
	require.False(t, ok)
	require.Nil(t, cache)
}
