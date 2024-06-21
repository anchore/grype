package v6

import (
	"fmt"
	"github.com/OneOfOne/xxhash"
)

func BlobDigest(content string) string {
	h := xxhash.New64()
	h.Write([]byte(content)) // TODO: handle error?
	return fmt.Sprintf("xx64:%x", h.Sum(nil))
}
