# Developing

There are a few useful things to know before diving into the codebase. This project depends on a few things being available like a vulnerability database, which you might want to create manually instead of retrieving a released version.

## Getting started

After cloning do the following:

1. run `go build ./cmd/grype` to get a binary named `main` from the source (use `-o <name>` to get a differently named binary), or optionally `go run ./cmd/grype` to run from source.

In order to run tests and build all artifacts:

1. run `make bootstrap` to download go mod dependencies, create the `/.tmp` dir, and download helper utilities (this only needs to be done once or when build tools are updated).
2. run `make` to run linting, tests, and other verifications to make certain everything is working alright.

The main make tasks for common static analysis and testing are `lint`, `format`, `lint-fix`, `unit`, and `integration`.

See `make help` for all the current make tasks.

## Relationship to Syft

Grype uses Syft as a library for all-things related to obtaining and parsing the given scan target (pulling container
images, parsing container images, indexing directories, cataloging packages, etc). Releases of Grype should
always use released versions of Syft (commits that are tagged and show up in the GitHub releases page). However,
continually integrating unreleased Syft changes into Grype incrementally is encouraged
(e.g. `go get github.com/anchore/syft@main`) as long as by the time a release is cut the Syft version is updated
to a released version (e.g. `go get github.com/anchore/syft@v<semantic-version>`).

## Inspecting the database

The currently supported database format is Sqlite3. Install `sqlite3` in your system and ensure that the `sqlite3` executable is available in your path. Ask `grype` about the location of the database, which will be different depending on the operating system:

```
$ go run ./cmd/grype db status
Location:  /Users/alfredo/Library/Caches/grype/db
Built:  2020-07-31 08:18:29 +0000 UTC
Current DB Version:  1
Require DB Version:  1
Status: Valid
```

The database is located within the XDG_CACHE_HOME path. To verify the database filename, list that path:

```
# OSX-specific path
$ ls -alh  /Users/alfredo/Library/Caches/grype/db
total 445392
drwxr-xr-x  4 alfredo  staff   128B Jul 31 09:27 .
drwxr-xr-x  3 alfredo  staff    96B Jul 31 09:27 ..
-rw-------  1 alfredo  staff   139B Jul 31 09:27 metadata.json
-rw-r--r--  1 alfredo  staff   217M Jul 31 09:27 vulnerability.db
```

Next, open the `vulnerability.db` with `sqlite3`:

```
$ sqlite3 /Users/alfredo/Library/Caches/grype/db/vulnerability.db
```

To make the reporting from Sqlite3 easier to read, enable the following:

```
sqlite> .mode column
sqlite> .headers on
```

List the tables:

```
sqlite> .tables
id                      vulnerability           vulnerability_metadata
```

In this example you retrieve a specific vulnerability from the `nvd` namespace:

```
sqlite> select * from vulnerability where (namespace="nvd" and package_name="libvncserver") limit 1;
id             record_source  package_name  namespace   version_constraint  version_format  cpes                                                         proxy_vulnerabilities
-------------  -------------  ------------  ----------  ------------------  --------------  -----------------------------------------------------------  ---------------------
CVE-2006-2450                 libvncserver  nvd         = 0.7.1             unknown         ["cpe:2.3:a:libvncserver:libvncserver:0.7.1:*:*:*:*:*:*:*"]  []
```
