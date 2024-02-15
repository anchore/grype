package sqlite

import (
	"database/sql"
	"encoding/json"
)

type NullString struct {
	sql.NullString
}

func NewNullString(s string, valid bool) NullString {
	return NullString{
		sql.NullString{
			String: s,
			Valid:  valid,
		},
	}
}

func ToNullString(v any) NullString {
	nullString := NullString{}
	nullString.Valid = false

	if v != nil {
		var stringValue string

		if s, ok := v.(string); ok {
			stringValue = s
		} else {
			vBytes, err := json.Marshal(v)
			if err != nil {
				// TODO: just no
				panic(err)
			}

			stringValue = string(vBytes)
		}

		if stringValue != "null" {
			nullString.String = stringValue
			nullString.Valid = true
		}
	}

	return nullString
}

func (v NullString) ToByteSlice() []byte {
	if v.Valid {
		return []byte(v.String)
	}

	return []byte("null")
}

func (v NullString) MarshalJSON() ([]byte, error) {
	if v.Valid {
		return json.Marshal(v.String)
	}

	return json.Marshal(nil)
}

func (v *NullString) UnmarshalJSON(data []byte) error {
	if data != nil && string(data) != "null" {
		v.Valid = true
		v.String = string(data)
	} else {
		v.Valid = false
	}
	return nil
}
