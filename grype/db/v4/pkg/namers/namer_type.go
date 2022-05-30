package namers

const (
	StockNamer  NamerType = "stock-namer"
	PythonNamer NamerType = "python-namer"
)

var AllNamerTypes = []NamerType{
	StockNamer,
	PythonNamer,
}

type NamerType string
