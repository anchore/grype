package match

type ExclusionProvider interface {
	GetRules(vulnerabilityId string) ([]IgnoreRule, error)
}
