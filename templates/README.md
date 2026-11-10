# Grype Templates

This folder contains a set of "helper" go templates you can use for your own reports.

## Template data model

Templates are executed against the same data as the JSON output (`-o json`), so template field names match the JSON keys: e.g. `.matches`, `.artifact.name`, `.vulnerability.id`, `.vulnerability.fix.versions`, `.source.target.userInput`.

Grype previously executed templates against an internal Go struct document (fields such as `.Matches`, `.Artifact.Name`, and `.Vulnerability.ID`). If you have an existing template written for that model, either update its field names to the JSON keys or run grype with the legacy model:

```
grype <image> -o template -t your-template.tmpl --template-legacy
```

(or set `output-template-legacy: true` in the grype config file).

Please feel free to extend and/or update the templates for your needs, be sure to contribute back into this folder any new templates!

Current templates:

<pre>
.
├── README.md
├── html.tmpl
├── junit.tmpl
├── csv.tmpl
└── table.tmpl
</pre>

## Table

This template mimics the "default" table output of Grype, there are some drawbacks to using the template vs the native output such as:

- unsorted
- duplicate rows
- no (wont-fix) logic

As you can see from the above list, it's not perfect but it's a start.

## HTML

Produces a nice html template with a dynamic table using datatables.js.

You can also modify the templating filter to limit the output to a subset.

Default includes all

```
    {{- if or (eq $vuln.vulnerability.severity "Critical") (eq $vuln.vulnerability.severity "High") (eq $vuln.vulnerability.severity "Medium") (eq $vuln.vulnerability.severity "Low") (eq $vuln.vulnerability.severity "Unknown") }}
```

We can limit it to only Critical, High, and Medium by editing the filter as follows

```
    {{- if or (eq $vuln.vulnerability.severity "Critical") (eq $vuln.vulnerability.severity "High") (eq $vuln.vulnerability.severity "Medium") }}
```

