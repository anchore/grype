package pkg

type FileOwner interface {
	OwnedFiles() []string
}
