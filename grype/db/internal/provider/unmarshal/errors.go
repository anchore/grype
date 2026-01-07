package unmarshal

import (
	"encoding/json"
	"fmt"
)

func handleJSONUnmarshalError(err error) error {
	if ute, ok := err.(*json.UnmarshalTypeError); ok { //nolint: errorlint
		return fmt.Errorf("unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)
	} else if se, ok := err.(*json.SyntaxError); ok { //nolint: errorlint
		return fmt.Errorf("syntax error: offset=%v, error=%w", se.Offset, se)
	}
	return err
}
