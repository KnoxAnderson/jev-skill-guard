"""Loader, policy, and scan orchestration tests, with Jev replaced by a stub."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from skill_guard import POLICIES, find_skills, load_skill, route, scan_skill
from skill_guard import scan as scan_module
from skill_guard.policy import STRUCTURAL_ACTION, TRAP_ACTION
from skill_guard.traps import BATTERIES, TRAP_CLASS

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
STRICT = POLICIES["strict"]


class StubJev:
    """Answers every question with a fixed probability, except where told otherwise."""

    def __init__(self, hot=None, fail_on=None):
        self.hot, self.fail_on, self.states = hot or {}, fail_on, []

    def ask(self, state, questions):
        self.states.append(state)
        where = state.get("file", {}).get("path", "")
        if self.fail_on == where:
            raise RuntimeError("boom")
        content = state.get("content", "")
        answers = {}
        for qid in questions:
            needle, probability = self.hot.get(qid, (None, 0.02))
            answers[qid] = {"noul": probability if needle and needle in content else 0.02}
        answers["severity"] = {"score": 0.1}
        return answers


def make_skill(tmp_path, files):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode())
    return tmp_path


SKILL_MD = "---\nname: demo\ndescription: Does a thing.\nallowed-tools: [Read, Bash]\n---\n# Demo\nDo the thing.\n"


def test_every_trap_has_a_class_and_an_action():
    asked = {qid for battery in BATTERIES.values() for qid in battery} - {"severity"}
    assert asked == set(TRAP_CLASS) == set(TRAP_ACTION)


def test_loader_reads_manifest_and_classifies_files(tmp_path):
    root = make_skill(tmp_path, {
        "SKILL.md": SKILL_MD, "scripts/run": "#!/bin/sh\necho hi\n", "ref/notes.md": "notes",
        "logo.png": b"\x89PNG\x00\x00", "node_modules/x/SKILL.md": "ignored",
    })
    skill = load_skill(root)
    assert (skill.name, skill.description, skill.allowed_tools) == ("demo", "Does a thing.", "Read, Bash")
    assert {f.path: f.kind for f in skill.files} == {
        "SKILL.md": "instructions", "scripts/run": "code", "ref/notes.md": "instructions", "logo.png": "binary",
    }
    assert skill.files[0].path == "SKILL.md"
    assert find_skills(root) == [root]


def test_symlink_out_of_the_skill_is_not_followed(tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("private")
    root = make_skill(tmp_path / "skill", {"SKILL.md": SKILL_MD})
    (root / "link.txt").symlink_to(outside)
    result = scan_skill(None, root)
    assert [f["path"] for f in result["files"]] == ["SKILL.md"]
    assert any("link.txt" in entry for entry in result["unscanned"])


def test_route_thresholds_and_precedence():
    assert route({"biased_framing": 0.2}, 0.0, STRICT) == "pass"
    assert route({"memory_poisoning": 0.5}, 0.0, STRICT) == "review"
    assert route({"memory_poisoning": 0.9}, 0.0, STRICT) == "block"
    assert route({"biased_framing": 0.99}, 0.0, STRICT) == "review"  # review-class trap
    assert route({"biased_framing": 0.99}, 2.5, STRICT) == "block"  # severity escalates it
    assert route({"data_exfiltration": 0.25}, 0.0, STRICT) == "review"  # per-trap override
    assert route({}, 0.0, STRICT, [{"name": "hidden_markup", "detail": ""}]) == "block"
    assert set(STRUCTURAL_ACTION.values()) <= {"block", "review"}


def test_batteries_follow_file_kind_and_whole_skill_is_scored(tmp_path):
    root = make_skill(tmp_path, {"SKILL.md": SKILL_MD, "run.sh": "#!/bin/sh\necho hi\n"})
    stub = StubJev()
    result = scan_skill(stub, root)
    assert result["action"] == "pass" and result["semantic"]
    by_path = {f["path"]: f for f in result["files"]}
    assert "hidden_instructions" in by_path["SKILL.md"]["nouls"]
    assert "covert_behaviour" in by_path["run.sh"]["nouls"]
    assert set(result["whole_skill"]["nouls"]) == set(BATTERIES["skill"]) - {"severity"}
    whole = next(s for s in stub.states if "files" in s)
    assert whole["skill"]["description"] == "Does a thing." and len(whole["files"]) == 2


def test_one_bad_file_blocks_the_skill(tmp_path):
    root = make_skill(tmp_path, {"SKILL.md": SKILL_MD, "ref/a.md": "fine", "ref/b.md": "PAYLOAD here"})
    result = scan_skill(StubJev(hot={"data_exfiltration": ("PAYLOAD", 0.95)}), root)
    by_path = {f["path"]: f["action"] for f in result["files"]}
    assert by_path == {"SKILL.md": "pass", "ref/a.md": "pass", "ref/b.md": "block"}
    assert result["action"] == "block"


def test_payload_past_the_first_chunk_is_still_scored(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_module, "CHUNK_CHARS", 1000)
    monkeypatch.setattr(scan_module, "CHUNK_OVERLAP", 100)
    padded = SKILL_MD + "filler line\n" * 300 + "PAYLOAD\n"
    root = make_skill(tmp_path, {"SKILL.md": padded})
    result = scan_skill(StubJev(hot={"embedded_jailbreak": ("PAYLOAD", 0.9)}), root)
    assert result["files"][0]["action"] == "block"


def test_file_too_long_to_score_fully_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_module, "CHUNK_CHARS", 200)
    monkeypatch.setattr(scan_module, "CHUNK_OVERLAP", 0)
    monkeypatch.setattr(scan_module, "MAX_CHUNKS", 2)
    root = make_skill(tmp_path, {"SKILL.md": SKILL_MD + "x" * 2000})
    assert scan_skill(StubJev(), root)["files"][0]["truncated"] is True


def test_api_failure_becomes_review_not_pass(tmp_path):
    root = make_skill(tmp_path, {"SKILL.md": SKILL_MD, "ref/a.md": "fine"})
    result = scan_skill(StubJev(fail_on="ref/a.md"), root)
    failed = next(f for f in result["files"] if f["path"] == "ref/a.md")
    assert failed["action"] == "review" and failed["structural"][0]["name"] == "scan_error"
    assert result["action"] == "review"


def test_normalized_text_is_what_the_model_sees(tmp_path):
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "PAYLOAD")
    root = make_skill(tmp_path, {"SKILL.md": SKILL_MD + hidden})
    stub = StubJev(hot={"hidden_instructions": ("PAYLOAD", 0.9)})
    result = scan_skill(stub, root)
    assert result["files"][0]["nouls"]["hidden_instructions"] == 0.9


def test_offline_samples_split_as_expected():
    actions = {p.name: scan_skill(None, p)["action"] for p in find_skills(SAMPLES)}
    assert actions["pdf-form-filler"] == actions["release-notes"] == "pass"
    assert actions["markdown-tidy"] == actions["env-doctor"] == "block"
    # Nothing structural marks these two; they are the case for the semantic pass.
    assert actions["api-client-helper"] == "pass"
    assert actions["review-assistant"] == actions["team-conventions"] == "review"
