#!/usr/bin/env python3
import os
import re
import sys
import json
import collections

INCLUDE_SEVERITY = False
NO_COMPARE_VALUE = "n/a"
QUALITY_GATE_THRESHOLD = 0.85
INDENT = "    "
IMAGE_QUALITY_GATE = collections.defaultdict(lambda: QUALITY_GATE_THRESHOLD, **{
    # not necessary if not comparing severity
    # "debian:10.5": 0.86,   # anchore is replacing "Negligible" severity with "Low" in some (all?) situations
    "alpine:3.12.0": 1.0,    # no known vulnerabilities
    "alpine-vuln:latest": 1.0,
    "python-vuln:latest": 1.0,
    "java-vuln:latest": 1.0,
})

# We additionally fail if an image is above a particular threshold. Why? We expect the lower threshold to be 90%,
# however additional functionality in grype is still being implemented, so this threshold may not be able to be met.
# In these cases the IMAGE_QUALITY_GATE is set to a lower value to allow the test to pass for known issues. Once these
# issues/enhancements are done we want to ensure that the lower threshold is bumped up to catch regression. The only way
# to do this is to select an upper threshold for images with known threshold values, so we have a failure that
# loudly indicates the lower threshold should be bumped.
IMAGE_UPPER_THRESHOLD = collections.defaultdict(lambda: 1, **{
})

Metadata = collections.namedtuple("Metadata", "version severity")
Package = collections.namedtuple("Package", "name type")
Vulnerability = collections.namedtuple("Vulnerability", "id package")


def clean(image: str) -> str:
    return os.path.basename(image.replace(":", "_"))


class InlineScan:

    report_tmpl = "{image}-{report}.json"

    def __init__(self, image, report_dir="./"):
        self.report_dir = report_dir
        self.image = image

    def _report_path(self, report):
        return os.path.join(
            self.report_dir,
            self.report_tmpl.format(image=clean(self.image), report=report),
        )

    def _enumerate_section(self, report, section):
        report_path = self._report_path(report=report)
        os_report_path = self._report_path(report="content-os")

        if os.path.exists(os_report_path) and not os.path.exists(report_path):
            # if the OS report is there but the target report is not, that is engine's way of saying "no findings"
            return

        with open(report_path) as json_file:
            data = json.load(json_file)
            for entry in data[section]:
                yield entry

    def vulnerabilities(self):
        vulnerabilities = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(report="vuln", section="vulnerabilities"):
            package = Package(
                name=entry["package_name"],
                type=entry["package_type"].lower(),
            )
            vulnerability = Vulnerability(
                id=entry["vuln"],
                package=package,
            )
            vulnerabilities.add(vulnerability)

            severity = entry["severity"]
            if not INCLUDE_SEVERITY:
                severity = NO_COMPARE_VALUE

            metadata[package.type][package] = Metadata(version=entry["package_version"], severity=severity)
        return vulnerabilities, metadata

    def packages(self):
        python_packages = self._python_packages()
        os_packages = self._os_packages()
        return python_packages | os_packages

    def _python_packages(self):
        packages = set()
        for entry in self._enumerate_section(
                report="content-python", section="content"
        ):
            package = Package(name=entry["package"], type=entry["type"].lower(),)
            packages.add(package)

        return packages

    def _os_packages(self):
        packages = set()
        for entry in self._enumerate_section(report="content-os", section="content"):
            package = Package(name=entry["package"], type=entry["type"].lower())
            packages.add(package)

        return packages


class Grype:

    report_tmpl = "{image}.json"

    def __init__(self, image, report_dir="./"):
        self.report_path = os.path.join(
            report_dir, self.report_tmpl.format(image=clean(image))
        )

    def _enumerate_section(self, section):
        with open(self.report_path) as json_file:
            data = json.load(json_file)
            for entry in data[section]:
                yield entry

    def vulnerabilities(self):
        vulnerabilities = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section(section="matches"):

            # normalize to inline
            pkg_type = entry["artifact"]["type"].lower()
            if pkg_type in ("wheel", "egg"):
                pkg_type = "python"
            elif pkg_type in ("deb",):
                pkg_type = "dpkg"
            elif pkg_type in ("java-archive",):
                pkg_type = "java"
            elif pkg_type in ("apk",):
                pkg_type = "apkg"

            package = Package(name=entry["artifact"]["name"], type=pkg_type,)

            vulnerability = Vulnerability(
                id=entry["vulnerability"]["id"],
                package=package,
            )
            vulnerabilities.add(vulnerability)

            severity = entry["vulnerability"]["severity"]
            if not INCLUDE_SEVERITY:
                severity = NO_COMPARE_VALUE

            # engine doesn't capture epoch info, so we cannot use it during comparison
            version = entry["artifact"]["version"]
            if re.match(r'^\d+:', version):
                version = ":".join(version.split(":")[1:])

            metadata[package.type][package] = Metadata(version=version, severity=severity)

        return vulnerabilities, metadata


def print_rows(rows):
    if not rows:
        return
    widths = []
    for col, _ in enumerate(rows[0]):
        width = max(len(row[col]) for row in rows) + 2  # padding
        widths.append(width)
    for row in rows:
        print("".join(word.ljust(widths[col_idx]) for col_idx, word in enumerate(row)))


def main(image):
    print(colors.bold+"Image:", image, colors.reset)

    if not INCLUDE_SEVERITY:
        print(colors.bold + colors.fg.orange + "Warning: not comparing severity", colors.reset)

    inline = InlineScan(image=image, report_dir="inline-reports")
    inline_vulnerabilities, inline_metadata = inline.vulnerabilities()

    grype = Grype(image=image, report_dir="grype-reports")
    grype_vulnerabilities, grype_metadata = grype.vulnerabilities()

    if len(inline.packages()) == 0:
        # we don't want to accidentally pass the vulnerability check if there were no packages discovered.
        # (we are purposefully selecting test images that are guaranteed to have packages, so this should never happen)
        print(colors.bold + colors.fg.red + "inline found no packages!", colors.reset)
        return 1

    if len(inline_vulnerabilities) == 0:
        if len(grype_vulnerabilities) == 0:
            print(colors.bold+"nobody found any vulnerabilities", colors.reset)
            return 0
        print(colors.bold+"inline does not have any vulnerabilities to compare to", colors.reset)
        return 0

    same_vulnerabilities = grype_vulnerabilities & inline_vulnerabilities
    if len(inline_vulnerabilities) == 0:
        percent_overlap_vulnerabilities = 0
    else:
        percent_overlap_vulnerabilities = (
            float(len(same_vulnerabilities)) / float(len(inline_vulnerabilities))
        ) * 100.0

    bonus_vulnerabilities = grype_vulnerabilities - inline_vulnerabilities
    missing_vulnerabilities = inline_vulnerabilities - grype_vulnerabilities

    inline_metadata_set = set()
    for vulnerability in inline_vulnerabilities:
        metadata = inline_metadata[vulnerability.package.type][vulnerability.package]
        inline_metadata_set.add((vulnerability.package, metadata))

    grype_overlap_metadata_set = set()
    for vulnerability in grype_vulnerabilities:
        metadata = grype_metadata[vulnerability.package.type][vulnerability.package]
        # we only want to really count mismatched metadata for packages that are at least found by inline
        if vulnerability.package in inline_metadata[vulnerability.package.type]:
            grype_overlap_metadata_set.add((vulnerability.package, metadata))

    same_metadata = grype_overlap_metadata_set & inline_metadata_set
    missing_metadata = inline_metadata_set - same_metadata
    if len(inline_metadata_set) == 0:
        percent_overlap_metadata = 0
    else:
        percent_overlap_metadata = (
            float(len(same_metadata)) / float(len(inline_metadata_set))
        ) * 100.0

    if len(bonus_vulnerabilities) > 0:
        rows = []
        print(colors.bold + "Grype found extra vulnerabilities:", colors.reset)
        for vulnerability in sorted(list(bonus_vulnerabilities)):
            metadata = grype_metadata[vulnerability.package.type][vulnerability.package]
            rows.append([INDENT, repr(vulnerability), repr(metadata)])
        print_rows(rows)
        print()

    if len(missing_vulnerabilities) > 0:
        rows = []
        print(colors.bold + "Grype missed vulnerabilities:", colors.reset)
        for vulnerability in sorted(list(missing_vulnerabilities)):
            metadata = inline_metadata[vulnerability.package.type][vulnerability.package]
            rows.append([INDENT, repr(vulnerability), repr(metadata)])
        print_rows(rows)
        print()

    if len(missing_metadata) > 0:
        rows = []
        print(colors.bold + "Grype mismatched metadata:", colors.reset)
        for inline_metadata_pair in sorted(list(missing_metadata)):
            pkg, metadata = inline_metadata_pair
            if pkg in grype_metadata[pkg.type]:
                grype_metadata_item = grype_metadata[pkg.type][pkg]
            else:
                grype_metadata_item = "--- MISSING ---"
            rows.append([INDENT, "for:", repr(pkg), ":", repr(grype_metadata_item), "!=", repr(metadata)])
        print_rows(rows)
        print()

    print(colors.bold+"Summary:", colors.reset)
    print("   Image: %s" % image)
    print("   Inline Vulnerabilities : %d" % len(inline_vulnerabilities))
    print("   Grype Vulnerabilities  : %d " % len(grype_vulnerabilities))
    print("                 (extra)  : %d (note: this is ignored in the analysis!)" % len(bonus_vulnerabilities))
    print("               (missing)  : %d " % len(missing_vulnerabilities))
    print(
        "   Baseline Vulnerabilities Matched : %2.1f %% (%d/%d vulnerability)"
        % (percent_overlap_vulnerabilities, len(same_vulnerabilities), len(inline_vulnerabilities))
    )
    print(
        "   Baseline Metadata Matched        : %2.1f %% (%d/%d metadata)"
        % (percent_overlap_metadata, len(same_metadata), len(inline_metadata_set))
    )

    overall_score = (percent_overlap_vulnerabilities + percent_overlap_metadata) / 2.0

    print(colors.bold + "   Overall Score: %2.1f %%" % overall_score, colors.reset)

    upper_gate_value = IMAGE_UPPER_THRESHOLD[image] * 100
    lower_gate_value = IMAGE_QUALITY_GATE[image] * 100
    if overall_score < lower_gate_value:
        print(colors.bold + "   Quality Gate: " + colors.fg.red + "FAILED (is not >= %d %%)\n" % lower_gate_value, colors.reset)
        return 1
    elif overall_score > upper_gate_value:
        print(colors.bold + "   Quality Gate: " + colors.fg.orange + "FAILED (lower threshold is artificially low and should be updated)\n", colors.reset)
        return 1
    else:
        print(colors.bold + "   Quality Gate: " + colors.fg.green + "pass (>= %d %%)\n" % lower_gate_value, colors.reset)

    return 0


class colors:
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("provide an image")

    rc = main(sys.argv[1])
    sys.exit(rc)
