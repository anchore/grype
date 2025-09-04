package v6

func ptr[T any](v T) *T {
	return &v
}
