"""Read a skill directory into something the two passes can work on.

A skill is a directory with a SKILL.md (YAML frontmatter, then instructions) and,
optionally, scripts and reference files beside it. Every file is in scope: the agent
can be told to read or run any of them, so a clean SKILL.md proves nothing about the
skill.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache"}
CODE_SUFFIXES = {
    ".py", ".sh", ".bash", ".zsh", ".fish", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl",
    ".ps1", ".php", ".go", ".lua", ".applescript", ".bat", ".cmd",
}
MAX_TEXT_BYTES = 1_000_000


@dataclass
class SkillFile:
    path: str  # relative to the skill root
    kind: str  # "instructions" | "code" | "binary"
    text: str = ""
    raw: bytes = b""
    truncated: bool = False


@dataclass
class Skill:
    root: Path
    name: str
    description: str
    allowed_tools: str
    files: list[SkillFile] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # symlinks out of the skill, etc.

    def manifest(self) -> dict[str, str]:
        """What the user is shown when deciding to install — the claim to check against."""
        return {
            "name": self.name,
            "description": self.description,
            "allowed_tools": self.allowed_tools,
        }


def find_skills(path: Path) -> list[Path]:
    """`path` itself if it is a skill, otherwise every skill directory beneath it."""
    if (path / "SKILL.md").is_file():
        return [path]
    return sorted(
        p.parent for p in path.rglob("SKILL.md") if not SKIP_DIRS & set(p.relative_to(path).parts)
    )


def _frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    _, _, rest = text.partition("\n")
    block, sep, _ = rest.partition("\n---")
    if not sep:
        return {}
    try:
        parsed = yaml.safe_load(block)
    except yaml.YAMLError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _classify(path: Path, raw: bytes) -> tuple[str, str]:
    if b"\x00" in raw[:8192]:
        return "binary", ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "binary", ""
    if path.suffix.lower() in CODE_SUFFIXES or text.startswith("#!"):
        return "code", text
    # Everything else readable — markdown, HTML, JSON, YAML, LaTeX, SVG — is something
    # the agent may be pointed at and take guidance from.
    return "instructions", text


def load_skill(root: Path) -> Skill:
    root = root.resolve()
    files: list[SkillFile] = []
    skipped: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if SKIP_DIRS & set(relative.parts) or path.is_dir():
            continue
        if path.is_symlink() and not path.resolve().is_relative_to(root):
            skipped.append(f"{relative} (symlink to outside the skill: {path.resolve()})")
            continue
        if not path.is_file():
            continue
        raw = path.read_bytes()
        truncated = len(raw) > MAX_TEXT_BYTES
        kind, text = _classify(path, raw[:MAX_TEXT_BYTES])
        files.append(SkillFile(str(relative), kind, text, raw if kind == "binary" else b"", truncated))

    # SKILL.md first: it is what the agent reads first and what the report should lead with.
    files.sort(key=lambda f: (f.path != "SKILL.md", f.path))
    meta = _frontmatter(next((f.text for f in files if f.path == "SKILL.md"), ""))
    tools = meta.get("allowed-tools", meta.get("allowed_tools", ""))
    return Skill(
        root=root,
        name=str(meta.get("name") or root.name),
        description=str(meta.get("description") or ""),
        allowed_tools=", ".join(map(str, tools)) if isinstance(tools, list) else str(tools or ""),
        files=files,
        skipped=skipped,
    )
