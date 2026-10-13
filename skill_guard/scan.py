"""High-level scan_skill() entry point: assess every file of a skill and route it.

Each text file goes through two independent passes:

- **Structural** (`detectors.py`): deterministic. Catches obfuscation, hidden markup,
  and capability shapes, and de-obfuscates the file so the semantic pass scores the
  real payload rather than the disguised one.
- **Semantic** (Jev): calibrated probabilities for the trap questions in `traps.py`,
  with the battery chosen by what the file is — prose the agent reads, or a script it
  runs.

Then the skill is scored once more as a whole, for what no single file shows: a
description that does not match the behaviour, or a payload split across files.

Any pass on any file can escalate on its own, and the skill takes the worst result.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import detectors
from .client import JevClient
from .loader import Skill, load_skill
from .policy import DEFAULT_POLICY, POLICIES, route, triggered, worst
from .traps import ABOUT, BATTERIES

CHUNK_CHARS = 20_000
CHUNK_OVERLAP = 500
MAX_CHUNKS = 6
SKILL_PASS_BUDGET = 60_000  # characters of file content shown to the whole-skill pass


def _chunks(text: str) -> tuple[list[str], bool]:
    """Split a long file so nothing past the first screenful goes unread.

    Padding a file to push the payload out of the scanner's window is the obvious
    evasion, so long files are scored chunk by chunk and the worst chunk wins. The
    cap exists only to bound cost; hitting it is reported, never silent.
    """
    step = CHUNK_CHARS - CHUNK_OVERLAP
    parts = [text[i : i + CHUNK_CHARS] for i in range(0, max(len(text), 1), step)]
    return parts[:MAX_CHUNKS], len(parts) > MAX_CHUNKS


def _ask(client: JevClient, state: dict[str, Any], battery_name: str) -> dict[str, Any]:
    battery = BATTERIES[battery_name]
    answers = client.ask(state=state, questions=battery)
    return {
        "nouls": {qid: answers[qid]["noul"] for qid in battery if qid != "severity"},
        "severity": answers["severity"]["score"],
    }


def _merge(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """Worst case across chunks: a file is as bad as its worst passage."""
    return {
        "nouls": {qid: max(p["nouls"][qid] for p in parts) for qid in parts[0]["nouls"]},
        "severity": max(p["severity"] for p in parts),
    }


def _skill_state(skill: Skill, normalized: dict[str, str]) -> dict[str, Any]:
    text_files = [f for f in skill.files if f.kind != "binary"]
    per_file = max(2_000, SKILL_PASS_BUDGET // max(len(text_files), 1))
    return {
        "about": ABOUT,
        "skill": skill.manifest(),
        "files": [
            {"path": f.path, "kind": f.kind, "content": normalized[f.path][:per_file]}
            for f in text_files
        ],
        "binary_files": [f.path for f in skill.files if f.kind == "binary"],
    }


def scan_skill(
    client: JevClient | None,
    root: Path,
    policy_name: str = DEFAULT_POLICY,
    max_workers: int = 4,
) -> dict[str, Any]:
    """Scan one skill directory and return an action with the evidence behind it.

    Pass `client=None` for a structural-only scan: no API key, no network, and no
    opinion on intent — useful as a fast first gate, not as a clearance.
    """
    skill = load_skill(root)
    policy = POLICIES[policy_name]
    reports: dict[str, dict[str, Any]] = {}
    normalized: dict[str, str] = {}
    jobs: list[tuple[str, dict[str, Any], str]] = []  # (file path or "", state, battery)

    for f in skill.files:
        if f.kind == "binary":
            hits = detectors.scan_binary(f.raw)
            reports[f.path] = {"kind": "binary", "structural": hits, "truncated": f.truncated}
            continue
        normalized[f.path], hits = detectors.scan(f.text, f.kind)
        parts, clipped = _chunks(normalized[f.path])
        reports[f.path] = {"kind": f.kind, "structural": hits, "truncated": f.truncated or clipped}
        for part in parts:
            state = {"about": ABOUT, "skill": skill.manifest(), "file": {"path": f.path, "kind": f.kind}, "content": part}
            jobs.append((f.path, state, f.kind))
    jobs.append(("", _skill_state(skill, normalized), "skill"))

    answers: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, str] = {}
    if client is not None:
        def run(job: tuple[str, dict[str, Any], str]) -> tuple[str, dict[str, Any] | Exception]:
            path, state, battery = job
            try:
                return path, _ask(client, state, battery)
            except Exception as exc:  # one unreadable file must not hide the rest
                return path, exc

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for path, outcome in pool.map(run, jobs):
                if isinstance(outcome, Exception):
                    errors[path] = f"{type(outcome).__name__}: {outcome}"
                else:
                    answers.setdefault(path, []).append(outcome)

    def finish(path: str, report: dict[str, Any]) -> dict[str, Any]:
        structural = [{"name": h.name, "detail": h.detail} for h in report.get("structural", [])]
        if path in errors:
            # Fail toward a human: an unscored file is not a cleared file.
            structural.append({"name": "scan_error", "detail": errors[path]})
        scored = _merge(answers[path]) if path in answers and path not in errors else None
        nouls = scored["nouls"] if scored else {}
        severity = scored["severity"] if scored else 0.0
        return {
            **report,
            "structural": structural,
            "nouls": nouls,
            "severity": severity,
            "findings": triggered(nouls, policy),
            "action": route(nouls, severity, policy, structural),
        }

    files = [{"path": path, **finish(path, report)} for path, report in reports.items()]
    whole = finish("", {"kind": "skill"})
    return {
        "skill": skill.name,
        "path": str(skill.root),
        "description": skill.description,
        "policy": policy_name,
        "semantic": client is not None,
        "action": worst([f["action"] for f in files] + [whole["action"]]),
        "whole_skill": whole,
        "files": files,
        # Named so the gap is visible: these were checked for embedded text only.
        "unscanned": [f.path for f in skill.files if f.kind == "binary"] + skill.skipped,
    }
