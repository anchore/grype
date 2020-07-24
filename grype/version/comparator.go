package version

type comparatorGenerator func(constraintUnit) (Comparator, error)

type Comparator interface {
	Compare(*Version) (int, error)
}
