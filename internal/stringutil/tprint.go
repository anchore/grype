package stringutil

import (
	"bytes"
	"text/template"
)

// Tprintf renders a string from a given template string and field values
func Tprintf(tmpl string, data map[string]interface{}) string {
	t := template.Must(template.New("").Parse(tmpl))
	buf := &bytes.Buffer{}
	if err := t.Execute(buf, data); err != nil {
		return ""
	}
	return buf.String()
}
