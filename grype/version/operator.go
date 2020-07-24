package version

import "fmt"

const (
	EQ  Operator = "="
	GT  Operator = ">"
	LT  Operator = "<"
	GTE Operator = ">="
	LTE Operator = "<="
)

type Operator string

func ParseOperator(op string) (Operator, error) {
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
	}
	return "", fmt.Errorf("unknown operator: '%s'", op)
}
