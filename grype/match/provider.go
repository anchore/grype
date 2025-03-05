package match

type ExclusionProvider interface {
	IgnoreRules(vulnerabilityID string) ([]IgnoreRule, error)
}
