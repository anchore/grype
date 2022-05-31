package resolver

const (
	Stock  Type = "stock-package-resolver"
	Python Type = "python-package-resolver"
	Java   Type = "java-package-resolver"
)

var AllTypes = []Type{
	Stock,
	Python,
	Java,
}

type Type string
