package match

type ExclusionProvider interface {
	GetRules(vulnerabilityID string) ([]IgnoreRule, error)
}
