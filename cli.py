#!/usr/bin/env python3
"""Scan agent skills for traps and print an install decision for each.

Usage:
    python cli.py                          # scan every sample skill, default policy
    python cli.py ~/.claude/skills         # scan every skill under a directory
    python cli.py path/to/skill --show     # full per-file breakdown
    python cli.py path/to/skill --offline  # structural pass only, no API key needed
    python cli.py path/to/skill --json     # machine-readable, for CI or a hook

Exits 2 if any skill is blocked and 1 if any needs review, so it can gate an install.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from skill_guard import DEFAULT_POLICY, POLICIES, JevClient, find_skills, scan_skill
from skill_guard.policy import STRUCTURAL_ACTION
from skill_guard.traps import TRAP_CLASS

ICON = {"pass": "  pass  ", "review": " review ", "block": " BLOCK  "}
EXIT = {"pass": 0, "review": 1, "block": 2}


def headline(result: dict) -> str:
    """The single most telling piece of evidence, for the one-line view."""
    parts = [(result["whole_skill"], "")] + [(f, f["path"]) for f in result["files"]]
    semantic = [(f["probability"], f["trap"], where) for part, where in parts for f in part["findings"]]
    if semantic:
        probability, trap, where = max(semantic)
        return f"{trap}={probability:.2f}" + (f" in {where}" if where else "")
    hits = [(STRUCTURAL_ACTION.get(h["name"], "review") != "block", h["name"], where) for part, where in parts for h in part["structural"]]
    if hits:
        _, name, where = min(hits)  # block-level evidence first
        return f"[{name}]" + (f" in {where}" if where else "")
    return ""


def show(result: dict) -> None:
    policy = POLICIES[result["policy"]]
    print(f"\n{result['skill']}  ->  {result['action'].upper()}  [policy={result['policy']}]")
    print(f"  {result['path']}")
    print(f"  declared: {' '.join(result['description'].split())[:200] or '(no description)'}")
    if not result["semantic"]:
        print("  structural pass only — intent was not assessed")
    else:
        print(
            f"  review >= {policy['review_threshold']:.2f}, action >= {policy['action_threshold']:.2f}, "
            f"severity blocks at {policy['severity_block']:.2f}"
        )
    for part in [{"path": "(whole skill)", **result["whole_skill"]}] + result["files"]:
        if part["action"] == "pass" and not part["structural"]:
            print(f"  [{ICON['pass']}] {part['path']}")
            continue
        note = "  (too long: only the first part was scored)" if part.get("truncated") else ""
        severity = f"  sev={part['severity']:.1f}" if part["nouls"] else ""
        print(f"  [{ICON[part['action']]}] {part['path']}{severity}{note}")
        for finding in part["findings"]:
            bar = "#" * round(finding["probability"] * 24)
            label = f"{TRAP_CLASS[finding['trap']]} / {finding['trap']}"
            print(f"      {label:<44}{finding['probability']:.2f}  {bar}")
        for hit in part["structural"]:
            print(f"      [{hit['name']}] {hit['detail']}")
    if result["unscanned"]:
        print("  not scored (binary or outside the skill): " + ", ".join(result["unscanned"]))


def main() -> None:
    load_dotenv(Path(__file__).parent / ".env")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", type=Path, help="skill directories, or directories containing skills")
    parser.add_argument("--policy", default=DEFAULT_POLICY, choices=POLICIES.keys())
    parser.add_argument("--show", action="store_true", help="print the per-file breakdown for every skill")
    parser.add_argument("--offline", action="store_true", help="structural detectors only; no API call")
    parser.add_argument("--json", action="store_true", help="print the full results as JSON")
    args = parser.parse_args()

    if not args.offline and "OPENROUTER_API_KEY" not in os.environ:
        sys.exit("Set OPENROUTER_API_KEY (see .env.example), or pass --offline for the structural pass alone.")

    roots = args.paths or [Path(__file__).parent / "samples"]
    skills = [skill for root in roots for skill in find_skills(root.expanduser())]
    if not skills:
        sys.exit(f"No SKILL.md found under: {', '.join(map(str, roots))}")

    client = None if args.offline else JevClient()
    results = [scan_skill(client, skill, args.policy) for skill in skills]

    if args.json:
        print(json.dumps(results, indent=2))
    elif args.show:
        for result in results:
            show(result)
    else:
        print(f"POLICY: {args.policy}" + ("  (offline: structural only)" if args.offline else "") + "\n")
        for result in results:
            print(f"[{ICON[result['action']]}] {result['skill']:<26} {headline(result)}")
    sys.exit(max(EXIT[result["action"]] for result in results))


if __name__ == "__main__":
    main()
