package version

import "fmt"

const (
	EQ  operator = "="
	GT  operator = ">"
	LT  operator = "<"
	GTE operator = ">="
	LTE operator = "<="
	OR  operator = "||"
	AND operator = ","
)

type operator string

func parseOperator(op string) (operator, error) {
	switch op {
	case string(EQ), "":
		return EQ, nil
	case string(GT):
		return GT, nil
	case string(GTE):
		return GTE, nil
	case string(LT):
		return LT, nil
	case string(LTE):
		return LTE, nil
	case string(OR):
		return OR, nil
	case string(AND):
		return AND, nil
	}
	return "", fmt.Errorf("unknown operator: '%s'", op)
}
