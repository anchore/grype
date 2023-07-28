#!/usr/bin/env python3

import subprocess
import sys
from typing import Optional

import click
from tabulate import tabulate
from dataclasses import dataclass, InitVar, field

import yardstick
from yardstick import store, comparison, artifact, arrange
from yardstick.cli import display, config
from yardstick.cli.explore.image_labels.label_manager import LabelManager

default_result_set = "pr_vs_latest_via_sbom"

@click.command()
@click.option("--image", "-i", "images", multiple=True, help="filter down to one or more images to validate with (don't use the full result set)")
@click.option("--verbose", "-v", "verbosity", count=True, help="show details of all comparisons")
@click.option("--result-set", "-r", default=default_result_set, help="the result set to use for the quality gate")
@click.option("--no-dry-run", "-d", is_flag=True, default=False, help="Print what would be done but change nothing")
def main(images: list[str], verbosity: int, result_set: str, no_dry_run: bool):
    # take 2 results and compare them and apply labels, and find diffs with those labels applied
    # do a relative comparison between two grype results, the output is distinct matches from either tool
    # apply labels to those distinct matches
    dry_run = True
    if no_dry_run:
        dry_run = False
    cfg = config.load()

    if not images:
        images = set()
        result_set_obj = store.result_set.load(name=result_set)
        for state in result_set_obj.state:
            images.add(state.config.image)
        images = sorted(list(images))

    print(f"images: {images}")
    label_entries = store.labels.load_for_image(images, year_max_limit=cfg.default_max_year)

    result_set_obj = store.result_set.load(name=result_set)
    affected_images = set()
    for image_str, result_states in sorted(result_set_obj.result_state_by_image.items()):
        if image_str not in images:
            continue
        descriptions = [s.config.ID for s in result_states]

        # get relative comparison of all results...
        relative_comparison = yardstick.compare_results(
            descriptions=descriptions, 
            year_max_limit=cfg.default_max_year,
        )

        results, label_entries, comparisons_by_result_id, stats_by_image_tool_pair = yardstick.compare_results_against_labels(descriptions=descriptions, year_max_limit=cfg.default_max_year, label_entries=label_entries)
        lineage = store.image_lineage.get(image_str)
        latest_release_tool, current_tool = guess_tool_orientation([r.config.tool for r in results])
        for result in relative_comparison.results:
            label_manager = LabelManager(result, label_entries, lineage) 
            print()
            print(f"{result.config.tool} ---")
            label_comparison = comparisons_by_result_id[result.ID]
            all_ids = (m.vulnerability.id for m in result.matches)
            for unique_match in sorted(relative_comparison.unique[result.ID]):
                labels = label_comparison.label_entries_by_match[unique_match.ID]
                labels2 = label_comparison.labels_by_match[unique_match.ID]
                if len(labels) != len(labels2):
                    raise RuntimeError("mismatched label entries")
                
                print(f"{result.ID}: {unique_match} ")
                for label in labels:
                    print(f"  {label}")

                # TODO: get label_entries, not just labels
                
                # guess scenario
                # print scenario
                # wrong alias means: we have the CVE version of this in the result still
                # FP all along means: removing the redundant package removed this finding
                # Redundant TP means: we have the same CVE in the result still against a different package

                # We're only interesting in TP labels
                tp_labels = [l for l in labels if l.label == artifact.Label.TruePositive]
                has_fp = any(l.label == artifact.Label.FalsePositive for l in labels)
                if has_fp:
                    print("skipping due to no TPs")
                    continue

                # msg = f"  >>> "

                if not unique_match.vulnerability.id.startswith("CVE-"):
                    cve = unique_match.vulnerability._get_cve()
                    equivalent_cve_still_in_results = any(m.vulnerability.id == cve for m in result.matches)
                    if equivalent_cve_still_in_results:
                        print(f"  >>> Deleting {result.ID} wrong alias: this is not a CVE")
                        # delete the label
                        affected_images.add(image_str)
                        delete_label(label_manager, tp_labels, dry_run)
                        # add_new_fp_label(image_str, unique_match, dry_run)
                    else:
                        print(f"  >>> Labeling {result.ID} as FP: FP all along: we were tricked into labeling this a TP (non CVE branch)")
                        affected_images.add(image_str)
                        # label as FP to protect against future regressions
                        delete_label(label_manager, tp_labels, dry_run)
                        add_new_fp_label(image_str, unique_match, dry_run)
                elif unique_match.vulnerability.id in all_ids:
                    print(f"  >>> Deleting {result.ID} Redundant TP: we found this ID in another package")
                    affected_images.add(image_str)
                    delete_label(label_manager, tp_labels, dry_run)
                    # add_new_fp_label(image_str, unique_match, dry_run)
                    # delete the label
                elif any(label.label == artifact.Label.TruePositive for label in labels):
                    # this is no longer present in the results at all;
                    # so removing the reundant package corrected this FP.
                    affected_images.add(image_str)
                    print(f"  >>> Relabeling {result.ID} as FP: FP all along: we were tricked into labeling this a TP")
                    delete_label(label_manager, tp_labels, dry_run)
                    add_new_fp_label(image_str, unique_match, dry_run)
                    # label as FP to protect against future regressions
                else:
                    msg = f"image: {image_str} result: {result.ID} match: {unique_match} labels: {labels}"
                    if not dry_run:
                        raise RuntimeError("unexpected scenario!" + msg)
                    print(f"  >>>>>>>>>>>>>>>>>>>>> Unexpected scenario: {msg}")
                print()
    print(affected_images)


def delete_label(label_manager: LabelManager, labels, dry_run: bool):
    for label in labels:
        if dry_run:
            print(f"would remove id {label.ID}")
        else:
            print(f"removing label entry {label.ID}")
            store.labels.delete([label.ID])

def add_new_fp_label(image: str, match: artifact.Match, dry_run: bool):
    # we want to be resilient in case we run this multiple times...
    # so if there is already a FP label, we don't want to add another one
    # add_label_entry(self, match: artifact.Match, label: artifact.Label, note: str = "")
    new_label = artifact.LabelEntry(
        vulnerability_id=match.vulnerability.id,
        image=artifact.ImageSpecifier(exact=image),
        package=match.package,
        label=artifact.Label.FalsePositive,
        note="Flagged as FP during grype1373 update",
        lookup_effective_cve=True,
    )
    if dry_run:
        print(f"would add new FP label to {match}")
    else:
        store.labels.save([new_label])

def guess_tool_orientation(tools: list[str]):
    if len(tools) != 2:
        raise RuntimeError("expected 2 tools, got %s" % tools)

    current_tool = None
    latest_release_tool = None
    for tool in tools:
        if tool.endswith("latest"):
            latest_release_tool = tool
            continue
        current_tool = tool

    if latest_release_tool is None:
        # "latest" value isn't accessible, so we do a best guess at which version is latest
        latest_release_tool, current_tool = sorted(tools)

    if current_tool is None:
        raise ValueError("current tool not found")
    return latest_release_tool, current_tool

if __name__ == '__main__':
    main()