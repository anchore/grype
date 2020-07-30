#!/usr/bin/env python2
import re
import os
import sys

pattern = re.compile(r'github.com/anchore/grype-db/pkg/db/v(?P<version>\d+)')

def main():
    schema_versions_found = set()

    for root, dirs, files in os.walk("."):
        for file in files:
            if not file.endswith(".go"):
                continue
            with open(os.path.join(root, file)) as f:
                for match in pattern.findall(f.read(), re.MULTILINE):
                    schema_versions_found.add(match)

    num_schemas = len(schema_versions_found)
    if num_schemas != 1:
        sys.exit("Found multiple schemas: %s" % repr(schema_versions_found))

    try:
        for x in schema_versions_found:
            int(x)
    except Exception:
        sys.exit("Non-numeric schema found: %s" % repr(schema_versions_found))

    print("Schemas Found: %s" % repr(schema_versions_found))

if __name__ == "__main__":
    main()
