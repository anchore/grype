package redact

import "github.com/anchore/go-logger/adapter/redact"

var store redact.Store

func Set(s redact.Store) {
	if store != nil {
		// if someone is trying to set a redaction store and we already have one then something is wrong. The store
		// that we're replacing might already have values in it, so we should never replace it.
		panic("replace existing redaction store (probably unintentional)")
	}
	store = s
}

func Get() redact.Store {
	return store
}

func Add(vs ...string) {
	if store == nil {
		// if someone is trying to add values that should never be output and we don't have a store then something is wrong.
		// we should never accidentally output values that should be redacted, thus we panic here.
		panic("cannot add redactions without a store")
	}
	store.Add(vs...)
}

func Apply(value string) string {
	if store == nil {
		// if someone is trying to add values that should never be output and we don't have a store then something is wrong.
		// we should never accidentally output values that should be redacted, thus we panic here.
		panic("cannot apply redactions without a store")
	}
	return store.RedactString(value)
}
