#!/usr/bin/env python3
import os
import sys
import json
import collections

QUALITY_GATE_THRESHOLD = 0.9

Metadata = collections.namedtuple("Metadata", "version")
Package = collections.namedtuple("Package", "name type")
Vulnerability = collections.namedtuple("Vulnerability", "cve package")


class InlineScan:

    report_tmpl = "{image}-{report}.json"

    def __init__(self, image, report_dir="./"):
        self.report_dir = report_dir
        self.image = image

    def _report_path(self, report):
        return os.path.join(
            self.report_dir,
            self.report_tmpl.format(image=self.image.replace(":", "_"), report=report),
        )

    def _enumerate_section(self, report, section):
        report_path = self._report_path(report=report)
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
                cve=entry["vuln"],
                package=package,
            )
            vulnerabilities.add(vulnerability)
            metadata[package.type][package] = Metadata(version=entry["package_version"])
        return vulnerabilities, metadata


class Grype:

    report_tmpl = "{image}.json"

    def __init__(self, image, report_dir="./"):
        self.report_path = os.path.join(
            report_dir, self.report_tmpl.format(image=image.replace(":", "_"))
        )

    def _enumerate_section(self):
        with open(self.report_path) as json_file:
            data = json.load(json_file)
            for entry in data:
                yield entry

    def vulnerabilities(self):
        vulnerabilities = set()
        metadata = collections.defaultdict(dict)
        for entry in self._enumerate_section():

            # normalize to inline
            pType = entry["package"]["type"].lower()
            if pType in ("wheel", "egg"):
                pType = "python"

            package = Package(name=entry["package"]["name"], type=pType,)

            vulnerability = Vulnerability(
                cve=entry["cve"],
                package=package,
            )
            vulnerabilities.add(vulnerability)
            metadata[package.type][package] = Metadata(version=entry["package"]["version"])
        return vulnerabilities, metadata


def main(image):
    inline = InlineScan(image=image, report_dir="inline-reports")
    inline_vulnerabilities, inline_metadata = inline.vulnerabilities()

    grype = Grype(image=image, report_dir="grype-reports")
    grype_vulnerabilities, grype_metadata = grype.vulnerabilities()

    if len(grype_vulnerabilities) == 0 and len(inline_vulnerabilities) == 0:
        print("nobody found any vulnerabilities")
        return 0

    same_vulnerabilities = grype_vulnerabilities & inline_vulnerabilities
    percent_overlap_vulnerabilities = (
        float(len(same_vulnerabilities)) / float(len(inline_vulnerabilities))
    ) * 100.0

    bonus_vulnerabilities = grype_vulnerabilities - inline_vulnerabilities
    missing_pacakges = inline_vulnerabilities - grype_vulnerabilities

    inline_metadata_set = set()
    for vulnerability in inline_vulnerabilities:
        metadata = inline_metadata[vulnerability.package.type][vulnerability.package]
        inline_metadata_set.add((vulnerability.package, metadata))

    grype_metadata_set = set()
    for vulnerability in grype_vulnerabilities:
        metadata = grype_metadata[vulnerability.package.type][vulnerability.package]
        grype_metadata_set.add((vulnerability.package, metadata))

    same_metadata = grype_metadata_set & inline_metadata_set
    percent_overlap_metadata = (
        float(len(same_metadata)) / float(len(inline_metadata_set))
    ) * 100.0

    if len(bonus_vulnerabilities) > 0:
        print("grype Bonus vulnerability:")
        for vulnerability in sorted(list(bonus_vulnerabilities)):
            print("    " + repr(vulnerability))
        print()

    if len(missing_pacakges) > 0:
        print("grype Missing vulnerability:")
        for vulnerability in sorted(list(missing_pacakges)):
            print("    " + repr(vulnerability))
        print()

    print("Inline Packages  : %d" % len(inline_vulnerabilities))
    print("grype Packages: %d" % len(grype_vulnerabilities))
    print()
    print(
        "Baseline Vulnerabilities Matched: %2.3f %% (%d/%d vulnerability)"
        % (percent_overlap_vulnerabilities, len(same_vulnerabilities), len(inline_vulnerabilities))
    )
    print(
        "Baseline Metadata        Matched: %2.3f %% (%d/%d metadata)"
        % (percent_overlap_metadata, len(same_metadata), len(inline_metadata_set))
    )

    overall_score = (percent_overlap_vulnerabilities + percent_overlap_metadata) / 2.0

    print("Overall Score: %2.3f %%" % overall_score)

    if overall_score < (QUALITY_GATE_THRESHOLD * 100):
        print("\nfailed quality gate (>= %d %%)\n" % (QUALITY_GATE_THRESHOLD * 100))
        return 1

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("provide an image")

    rc = main(sys.argv[1])
    sys.exit(rc)
