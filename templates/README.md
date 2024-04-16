# Grype Templates

This folder contains a set of "helper" go templates you can use for your own reports.

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

This template mimics the "default" table output of Grype, there are some drawbacks using the template vs the native output such as:

- unsorted
- duplicate rows
- no (wont-fix) logic

As you can see from the above list, it's not perfect but it's a start.

## HTML

Produces a nice html template with a dynamic table using datatables.js.

You can also modify the templating filter to limit the output to a subset.

Default includes all

```
    {{- if or (eq $vuln.Vulnerability.Severity "Critical") (eq $vuln.Vulnerability.Severity "High") (eq $vuln.Vulnerability.Severity "Medium") (eq $vuln.Vulnerability.Severity "Low") (eq $vuln.Vulnerability.Severity "Unknown") }}
```

We can limit it to only Critical, High, and Medium by editing the filter as follows

```
    {{- if or (eq $vuln.Vulnerability.Severity "Critical") (eq $vuln.Vulnerability.Severity "High") (eq $vuln.Vulnerability.Severity "Medium") }}
```

