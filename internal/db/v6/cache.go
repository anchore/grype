package v6

import (
	"context"
	"sync"
)

const (
	cpesTableCacheKey             = "cpes"
	packagesTableCacheKey         = "packages"
	operatingSystemsTableCacheKey = "operating_systems"
	vulnerabilitiesTableCacheKey  = "vulnerabilities"
)

const cacheKey = contextKey("multiModelCache")

type contextKey string

type cachable interface {
	cacheKey() string
	tableName() string
}

type cacheIDManager interface {
	rowID() ID
	setRowID(ID)
}

type cacheStringIDManager interface {
	rowID() string
	setRowID(string)
}

func withCacheContext(ctx context.Context, c *cache) context.Context {
	return context.WithValue(ctx, cacheKey, c)
}

func cacheFromContext(ctx context.Context) (*cache, bool) {
	c, ok := ctx.Value(cacheKey).(*cache)
	return c, ok
}

type cache struct {
	mu      sync.RWMutex
	idKeys  map[string]map[string]ID
	strKeys map[string]map[string]string
}

func newCache() *cache {
	return &cache{
		idKeys:  make(map[string]map[string]ID),
		strKeys: make(map[string]map[string]string),
	}
}

func (c *cache) getID(ca cachable) (ID, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if tableCache, exists := c.idKeys[ca.tableName()]; exists {
		id, found := tableCache[ca.cacheKey()]
		return id, found
	}
	return 0, false
}

func (c *cache) getString(ca cachable) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if tableCache, exists := c.strKeys[ca.tableName()]; exists {
		id, found := tableCache[ca.cacheKey()]
		return id, found
	}
	return "", false
}

func (c *cache) set(ca cachable) {
	switch cam := ca.(type) {
	case cacheIDManager:
		c.setIDEntry(cam.rowID(), ca)
	case cacheStringIDManager:
		c.setStringEntry(cam.rowID(), ca)
	default:
		panic("unsupported cacheable type")
	}
}

func (c *cache) setStringEntry(id string, ca cachable) {
	table := ca.tableName()
	key := ca.cacheKey()

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.strKeys[table]; !exists {
		c.strKeys[table] = make(map[string]string)
	}

	c.strKeys[table][key] = id
}

func (c *cache) setIDEntry(id ID, ca cachable) {
	table := ca.tableName()
	key := ca.cacheKey()

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.idKeys[table]; !exists {
		c.idKeys[table] = make(map[string]ID)
	}

	c.idKeys[table][key] = id
}
