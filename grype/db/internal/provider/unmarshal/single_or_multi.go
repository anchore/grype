package unmarshal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func unmarshalSingleOrMulti[T interface{}](reader io.Reader) ([]T, error) {
	var entry T

	var buf bytes.Buffer
	r := io.TeeReader(reader, &buf)

	dec := json.NewDecoder(r)
	err := dec.Decode(&entry)
	if err == nil {
		return []T{entry}, nil
	}

	// TODO: enhance the error handling to return the original error if the item is found to not be an array of items

	var entries []T
	dec = json.NewDecoder(io.MultiReader(&buf, reader))

	if err = dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("unable to decode vulnerability: %w", handleJSONUnmarshalError(err))
	}
	return entries, nil
}
