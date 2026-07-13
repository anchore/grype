package golang

import "strings"

// groupSymbols groups fully-qualified symbol names by their owning package import path, mirroring the
// grouped shape syft produces in GolangBinaryBuildinfoEntry.Symbols (import path -> local symbol names,
// with the import path prefix stripped). It lets the fixtures below stay readable flat lists of the
// fully-qualified names a binary actually carries.
func groupSymbols(names ...string) map[string][]string {
	out := map[string][]string{}
	for _, name := range names {
		importPath := symbolImportPath(name)
		local := name
		if importPath != "" {
			local = strings.TrimPrefix(name, importPath+".")
		}
		out[importPath] = append(out[importPath], local)
	}
	return out
}

// symbolImportPath derives the owning package import path from a fully-qualified symbol name: everything
// up to the first "." after the final "/". Type arguments are stripped first so their slashes and dots do
// not corrupt the split.
func symbolImportPath(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 {
		if j := strings.LastIndexByte(name, ']'); j >= 0 {
			name = name[:i] + name[j+1:]
		}
	}
	slash := strings.LastIndex(name, "/")
	dot := strings.IndexByte(name[slash+1:], '.')
	if dot < 0 {
		return ""
	}
	return name[:slash+1+dot]
}
