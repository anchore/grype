# Grype Templates

This folder contains a set of "helper" go templates you can use for your own reports.

Please feel free to extend and/or update the templates for your needs, be sure to contribute back into this folder any new templates!

Current templates:

<pre>
.
├── README.md
└── table.tmpl
</pre>

## Table

This template mimics the "default" table output of Grype, there are some drawbacks using the template vs the native output such as:

- unsorted
- duplicate rows
- no (wont-fix) logic

As you can see from the above list, it's not perfect but it's a start.
