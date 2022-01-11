#!/usr/bin/env python
import re
import os
import sys
import collections

dir_pattern = r'grype/db/v(?P<version>\d+)'
db_dir_regex = re.compile(dir_pattern)
import_regex = re.compile(rf'github.com/anchore/grype/{dir_pattern}')


def report_schema_versions_found(title, schema_to_locations):
    for schema, locations in sorted(schema_to_locations.items()):
        print(f"{title} schema: {schema}")
        for location in locations:
            print(f"  {location}")
    print()


def assert_single_schema_version(schema_to_locations):
    schema_versions_found = list(schema_to_locations.keys())
    try:
        for x in schema_versions_found:
            int(x)
    except ValueError:
        sys.exit("Non-numeric schema found: %s" % ", ".join(schema_versions_found))

    if len(schema_to_locations) > 1:
        sys.exit("Found multiple schemas: %s" % ", ".join(schema_versions_found))
    elif len(schema_to_locations) == 0:
        sys.exit("No schemas found!")


def find_db_schema_usages(filter_out_regexes=None, keep_regexes=None):
    schema_to_locations = collections.defaultdict(list)

    for root, dirs, files in os.walk("."):
        for file in files:
            if not file.endswith(".go"):
                continue
            location = os.path.join(root, file)

            if filter_out_regexes:
                do_filter = False
                for regex in filter_out_regexes:
                    if regex.findall(location):
                        do_filter = True
                        break
                if do_filter:
                    continue

            if keep_regexes:
                do_keep = False
                for regex in keep_regexes:
                    if regex.findall(location):
                        do_keep = True
                        break
                if not do_keep:
                    continue

            # keep track of all of the imports (from this point on, this is only possible consumers of db/v# code
            with open(location) as f:
                for match in import_regex.findall(f.read(), re.MULTILINE):
                    schema_to_locations[match].append(location)

    return schema_to_locations


def assert_schema_version_prefix(schema, locations):
    for location in locations:
        if f"/grype/db/v{schema}" not in location:
            sys.exit(f"found cross-schema reference: {location}")


def validate_schema_consumers():
    schema_to_locations = find_db_schema_usages(filter_out_regexes=[db_dir_regex])
    report_schema_versions_found("Consumers of", schema_to_locations)
    assert_single_schema_version(schema_to_locations)
    print("Consuming schema versions found: %s" % list(schema_to_locations.keys())[0])


def validate_schema_definitions():
    schema_to_locations = find_db_schema_usages(keep_regexes=[db_dir_regex])
    report_schema_versions_found("Definitions of", schema_to_locations)
    # make certain that each definition keeps out of other schema definitions
    for schema, locations in schema_to_locations.items():
        assert_schema_version_prefix(schema, locations)
    print("Verified that schema definitions don't cross-import")


def main():
    validate_schema_definitions()
    print()
    validate_schema_consumers()


if __name__ == "__main__":
    main()
