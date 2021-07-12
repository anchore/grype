#!/usr/bin/env python
import re
import os
import sys
import collections

pattern = re.compile(r'github.com/anchore/grype-db/pkg/db/v(?P<version>\d+)')


def report_schema_versions_found(schema_to_locations):
    for schema, locations in sorted(schema_to_locations.items()):
        print("Schema: %s" % schema)
        for location in locations:
            print("  %s" % location)
    print()


def validate(schema_to_locations):
    schema_versions_found = schema_to_locations.keys()
    try:
        for x in schema_versions_found:
            int(x)
    except Exception:
        sys.exit("Non-numeric schema found: %s" % ", ".join(list(schema_versions_found)))

    if len(schema_to_locations) > 1:
        sys.exit("Found multiple schemas: %s" % ", ".join(list(schema_versions_found)))
    elif len(schema_to_locations) == 0:
        sys.exit("No schemas found!")


def main():
    schema_to_locations = collections.defaultdict(list)

    for root, dirs, files in os.walk("."):
        for file in files:
            if not file.endswith(".go"):
                continue
            location = os.path.join(root, file)
            with open(location) as f:
                for match in pattern.findall(f.read(), re.MULTILINE):
                    schema_to_locations[match].append(location)

    report_schema_versions_found(schema_to_locations)
    validate(schema_to_locations)
    print("Schema Version Found: %s" % list(schema_to_locations.keys())[0])


if __name__ == "__main__":
    main()
