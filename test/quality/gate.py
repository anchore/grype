#!/usr/bin/env python3 -u
import logging
import os
import re
import subprocess
import sys
from typing import Optional

import click
from tabulate import tabulate
from dataclasses import dataclass, InitVar, field

import yardstick
from yardstick import store, comparison, artifact, arrange
from yardstick.cli import display, config


# see the .yardstick.yaml configuration for details
default_result_set = "pr_vs_latest_via_sbom"
yardstick.utils.grype_db.raise_on_failure(False)

@dataclass
class Gate:
    label_comparisons: InitVar[Optional[list[comparison.AgainstLabels]]]
    label_comparison_stats: InitVar[Optional[comparison.ImageToolLabelStats]]

    reasons: list[str] = field(default_factory=list)

    def __post_init__(self, label_comparisons: Optional[list[comparison.AgainstLabels]], label_comparison_stats: Optional[comparison.ImageToolLabelStats]):
        if not label_comparisons and not label_comparison_stats:
            return 
    
        reasons = []

        # - fail when current F1 score drops below last release F1 score (or F1 score is indeterminate)
        # - fail when indeterminate % > 10%
        # - fail when there is a rise in FNs
        latest_release_tool, current_tool = guess_tool_orientation(label_comparison_stats.tools)

        latest_release_comparisons_by_image = {comp.config.image: comp for comp in label_comparisons if comp.config.tool == latest_release_tool }
        current_comparisons_by_image = {comp.config.image: comp for comp in label_comparisons if comp.config.tool == current_tool }

        for image, comp in current_comparisons_by_image.items():
            latest_f1_score = latest_release_comparisons_by_image[image].summary.f1_score
            current_f1_score = comp.summary.f1_score
            if current_f1_score < latest_f1_score:
                reasons.append(f"current F1 score is lower than the latest release F1 score: {bcolors.BOLD+bcolors.UNDERLINE}current={current_f1_score:0.2f} latest={latest_f1_score:0.2f}{bcolors.RESET} image={image}")

            if comp.summary.indeterminate_percent > 10:
                reasons.append(f"current indeterminate matches % is greater than 10%: {bcolors.BOLD+bcolors.UNDERLINE}current={comp.summary.indeterminate_percent:0.2f}%{bcolors.RESET} image={image}")
    
            latest_fns = latest_release_comparisons_by_image[image].summary.false_negatives
            current_fns = comp.summary.false_negatives
            if current_fns > latest_fns:
                reasons.append(f"current false negatives is greater than the latest release false negatives: {bcolors.BOLD+bcolors.UNDERLINE}current={current_fns} latest={latest_fns}{bcolors.RESET} image={image}")

        self.reasons = reasons

    def passed(self):
        return len(self.reasons) == 0

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
        current_tool, latest_release_tool = sorted(tools)

    if current_tool is None:
        raise ValueError("current tool not found")
    return latest_release_tool, current_tool

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def show_results_used(results: list[artifact.ScanResult]):
    print(f"   Results used:")
    for idx, result in enumerate(results):
        branch = "├──"
        if idx == len(results) - 1:
            branch = "└──"
        print(f"    {branch} {result.ID} : {result.config.tool} against {result.config.image}")
    print()

def validate(cfg: config.Application, result_set: str, images: list[str], always_run_label_comparison: bool, verbosity: int, label_entries: Optional[list[artifact.LabelEntry]] = None):
    print(f"{bcolors.HEADER}{bcolors.BOLD}Validating with {result_set!r}", bcolors.RESET)
    result_set_obj = store.result_set.load(name=result_set)

    ret = []
    for image, result_states in result_set_obj.result_state_by_image.items():
        if images and image not in images:
            print("Skipping image:", image)
            continue
        print()
        print("Testing image:", image)
        for state in result_states:
            print("   ", f"with {state.request.tool}")
        print()

        gate = validate_image(cfg, [s.config.path for s in result_states], always_run_label_comparison=always_run_label_comparison, verbosity=verbosity, label_entries=label_entries)
        ret.append(gate)

        failure = not gate.passed()
        if failure:
            print(f"{bcolors.FAIL}{bcolors.BOLD}Failed quality gate{bcolors.RESET}")
        for reason in gate.reasons:
            print(f"   - {reason}")

        print()
        size = 120
        print("▁"*size)
        print("░"*size)
        print("▔"*size)
    return ret

def validate_image(cfg: config.Application, descriptions: list[str], always_run_label_comparison: bool, verbosity: int, label_entries: Optional[list[artifact.LabelEntry]] = None):
    # do a relative comparison
    # - show comparison summary (no gating action)
    # - list out all individual match differences

    print(f"{bcolors.HEADER}Running relative comparison...", bcolors.RESET)
    relative_comparison = yardstick.compare_results(descriptions=descriptions, year_max_limit=cfg.default_max_year)
    show_results_used(relative_comparison.results)

    # show the relative comparison results
    if verbosity > 0:
        details = verbosity > 1
        display.preserved_matches(relative_comparison, details=details, summary=True, common=False)
        print()

    # bail if there are no differences found
    if not always_run_label_comparison and not sum([len(relative_comparison.unique[result.ID]) for result in relative_comparison.results]):
        print("no differences found between tool results")
        return Gate(None, None)

    # do a label comparison
    print(f"{bcolors.HEADER}Running comparison against labels...", bcolors.RESET)
    results, label_entries, comparisons_by_result_id, stats_by_image_tool_pair = yardstick.compare_results_against_labels(descriptions=descriptions, year_max_limit=cfg.default_max_year, label_entries=label_entries)
    show_results_used(results)

    if verbosity > 0:
        show_fns = verbosity > 1
        display.label_comparison(
                results,
                comparisons_by_result_id,
                stats_by_image_tool_pair,
                show_fns=show_fns,
                show_summaries=True,
            )

    latest_release_tool, current_tool = guess_tool_orientation([r.config.tool for r in results])

    # show the relative comparison unique differences paired up with label conclusions (TP/FP/FN/TN/Unknown)
    all_rows: list[list[Any]] = []
    for result in relative_comparison.results:
        label_comparison = comparisons_by_result_id[result.ID]
        for unique_match in relative_comparison.unique[result.ID]:
            labels = label_comparison.labels_by_match[unique_match.ID]
            if not labels:
                label = "(unknown)"
            elif len(set(labels)) > 1:
                label = ", ".join([l.name for l in labels])
            else:
                label = labels[0].name
            

            color = ""
            commentary = ""
            if result.config.tool == latest_release_tool:
                # the tool which found the unique result is the latest release tool...
                if label == artifact.Label.TruePositive.name:
                    # drats! we missed a case (this is a new FN)
                    color = bcolors.FAIL
                    commentary = "(this is a new FN 😱)"
                elif artifact.Label.FalsePositive.name in label:
                    # we got rid of a FP! ["hip!", "hip!"]
                    color = bcolors.OKBLUE
                    commentary = "(got rid of a former FP 🙌)"
            else:
                # the tool which found the unique result is the current tool...
                if label == artifact.Label.TruePositive.name:
                    # highest of fives! we found a new TP that the previous tool release missed!
                    color = bcolors.OKBLUE
                    commentary = "(this is a new TP 🙌)"
                elif artifact.Label.FalsePositive.name in label:
                    # welp, our changes resulted in a new FP... not great, maybe not terrible?
                    color = bcolors.FAIL
                    commentary = "(this is a new FP 😱)"

            all_rows.append(
                [
                    f"{color}{result.config.tool} ONLY{bcolors.RESET}",
                    f"{color}{unique_match.package.name}@{unique_match.package.version}{bcolors.RESET}",
                    f"{color}{unique_match.vulnerability.id}{bcolors.RESET}",
                    f"{color}{label}{bcolors.RESET}",
                    f"{commentary}",
                ]
            )

    def escape_ansi(line):
        ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', line)

    # sort but don't consider ansi escape codes
    all_rows = sorted(all_rows, key=lambda x: escape_ansi(str(x[0]+x[1]+x[2]+x[3])))
    if len(all_rows) == 0:
        print("No differences found between tooling (with labels)")
    else:
        print("Match differences between tooling (with labels):")
        indent = "   "
        print(indent + tabulate([["TOOL PARTITION", "PACKAGE", "VULNERABILITY", "LABEL", "COMMENTARY"]]+all_rows, tablefmt="plain").replace("\n", "\n" + indent) + "\n")


    # populate the quality gate with data that can evaluate pass/fail conditions
    return Gate(label_comparisons=comparisons_by_result_id.values(), label_comparison_stats=stats_by_image_tool_pair)

@click.command()
@click.option("--image", "-i", "images", multiple=True, help="filter down to one or more images to validate with (don't use the full result set)")
@click.option("--label-comparison", "-l", "always_run_label_comparison", is_flag=True, help="run label comparison irregardless of relative comparison results")
@click.option("--breakdown-by-ecosystem", "-e", is_flag=True, help="show label comparison results broken down by ecosystem")
@click.option("--verbose", "-v", "verbosity", count=True, help="show details of all comparisons")
@click.option("--result-set", "-r", default=default_result_set, help="the result set to use for the quality gate")
def main(images: list[str], always_run_label_comparison: bool, breakdown_by_ecosystem: bool, verbosity: int, result_set: str):
    cfg = config.load()
    setup_logging(verbosity)

    # let's not load any more labels than we need to, base this off of the images we're validating
    if not images:
        images = set()
        result_set_obj = store.result_set.load(name=result_set)
        for state in result_set_obj.state:
            images.add(state.config.image)
        images = sorted(list(images))
 
    print("Loading label entries...", end=" ")
    label_entries = store.labels.load_for_image(images, year_max_limit=cfg.default_max_year)
    print(f"done! {len(label_entries)} entries loaded")

    result_sets = [result_set] # today only one result set is supported, but more can be added
    gates = []
    for result_set in result_sets:
        gates.extend(validate(cfg, result_set, images=images, always_run_label_comparison=always_run_label_comparison, verbosity=verbosity, label_entries=label_entries))
        print()
    
        if breakdown_by_ecosystem:
            print(f"{bcolors.HEADER}Breaking down label comparison by ecosystem performance...", bcolors.RESET)
            results_by_image, label_entries, stats = yardstick.compare_results_against_labels_by_ecosystem(result_set=result_set, year_max_limit=cfg.default_max_year, label_entries=label_entries)
            display.labels_by_ecosystem_comparison(
                results_by_image,
                stats,
                show_images_used=False,
            )
            print()

    failure = not all([gate.passed() for gate in gates])
    if failure:
        print("Reasons for quality gate failure:")
    for gate in gates:
        for reason in gate.reasons:
            print(f"   - {reason}")

    if failure:
        print()
        print(f"{bcolors.FAIL}{bcolors.BOLD}Quality gate FAILED{bcolors.RESET}")
        sys.exit(1)
    else:
        print(f"{bcolors.OKGREEN}{bcolors.BOLD}Quality gate passed!{bcolors.RESET}")


def setup_logging(verbosity: int):
    # pylint: disable=redefined-outer-name, import-outside-toplevel
    import logging.config

    if verbosity in [0, 1, 2]:
        log_level = "WARN"
    elif verbosity == 3:
        log_level = "INFO"
    else:
        log_level = "DEBUG"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    # [%(module)s.%(funcName)s]
                    "format": "%(asctime)s [%(levelname)s] %(message)s",
                    "datefmt": "",
                },
            },
            "handlers": {
                "default": {
                    "level": log_level,
                    "formatter": "standard",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "": {  # root logger
                    "handlers": ["default"],
                    "level": log_level,
                },
            },
        }
    )

if __name__ == '__main__':
    main()