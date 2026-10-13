# jev-skill-guard

Scans agent skills (a `SKILL.md` plus the scripts and reference files beside it) before
you install them, and returns `block`, `review`, or `pass` with the evidence. Built the
same way as [jev-guard](../jev-guard): deterministic detectors plus TypeSafe's Jev
decision model, called through OpenRouter's Decisions API (`~typesafe/jev-latest`).

What it looks for comes from *AI Agent Traps* (Franklin, Tomašev, Jacobs, Leibo,
Osindero — Google DeepMind), which sorts adversarial content by the part of the agent
it targets. A skill is that kind of content with unusually good access: the agent loads
it on purpose and follows it with your shell.

## How it works

Every text file in the skill goes through two independent passes, and either can
escalate on its own:

1. **Structural** (`skill_guard/detectors.py`) — deterministic. De-obfuscates the file
   (Unicode tag smuggling, zero-width characters, homoglyphs, base64 that decodes to
   instructions), then flags what is attacker-shaped as syntax: instructions inside
   HTML comments or undisplayed elements, link text that disagrees with its
   destination, image URLs with a slot for data, scripts that read a credential store
   and send something out, `curl | sh`, writes to the agent's own memory or config.
2. **Semantic** (Jev) — one call per file, asking the trap questions in
   `skill_guard/traps.py`. Which battery is asked depends on what the file is: prose
   the agent reads gets the 15-question instruction battery; a script it runs gets the
   7-question code battery.

Then the skill is scored once more **as a whole**, for what no single file shows — a
description that does not match the behaviour, or a payload split across files.

The skill takes the worst result of any pass on any file. A skill is supposed to
instruct the agent, so "contains instructions" is never a finding; every question turns
on whether the content serves the purpose the skill declares to the person installing
it.

## The questions, mapped to the paper

| Paper class (target) | Paper trap | Question | Where |
|---|---|---|---|
| Content Injection (perception) | Web-standard obfuscation | `hidden_instructions` | prose + detectors |
| | Syntactic masking | `syntactic_masking` | prose + detectors |
| | Dynamic cloaking | `dynamic_cloaking` — instructions fetched at run time, or gated on who is running | prose, code |
| | Steganographic payloads | *text-only model: binaries get a strings/trailer check and are listed as unscanned* | detectors |
| | (the class as a whole) | `scope_mismatch`, `covert_behaviour` — what the user is shown vs. what runs | whole skill, code |
| Semantic Manipulation (reasoning) | Biased phrasing, framing, priming | `biased_framing` | prose |
| | Oversight & critic evasion | `oversight_evasion` — including text addressed to this scanner | prose |
| | Persona hyperstition | `persona_hyperstition` | prose |
| Cognitive State (memory) | RAG knowledge poisoning | `knowledge_poisoning` | prose |
| | Latent memory poisoning | `memory_poisoning` | prose, code + detectors |
| | Contextual learning traps | `contextual_learning` — poisoned examples | prose |
| Behavioural Control (action) | Embedded jailbreak sequences | `embedded_jailbreak` | prose |
| | Data exfiltration traps | `data_exfiltration` | prose, code + detectors |
| | Sub-agent spawning traps | `subagent_spawning` | prose, code |
| | (unauthorised actions generally) | `unauthorized_action`, `privilege_overreach` | code, whole skill |
| Systemic (multi-agent) | Compositional fragment traps | `compositional_fragments` | whole skill |
| | Interdependence cascades | `self_propagation` — the skill spreading itself | prose, code |
| | Sybil attacks | `sybil_identities` | prose |
| | Congestion traps, tacit collusion | *not covered — properties of a population of agents, not visible in one skill* | — |
| Human-in-the-Loop (overseer) | Approval fatigue, automation bias | `overseer_deception` | prose |

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then paste in your OPENROUTER_API_KEY
```

## Run it

```bash
python cli.py                           # scan the sample skills
python cli.py ~/.claude/skills --show   # every skill under a directory, full breakdown
python cli.py path/to/skill --offline   # structural pass only: no key, no network
python cli.py path/to/skill --json      # machine-readable
pytest tests/                           # offline tests, no API key needed
```

The exit code is 2 if anything is blocked and 1 if anything needs review, so it can
gate an install script or CI job.

```python
from pathlib import Path
from skill_guard import JevClient, scan_skill

result = scan_skill(JevClient(), Path("path/to/skill"))
# result["action"] -> "block" | "review" | "pass"
# result["files"][i] -> {"path", "kind", "action", "findings", "structural", "nouls", "severity"}
# result["whole_skill"], result["unscanned"]
```

## What has been measured

Two small corpora, one run each, strict policy:

| Corpus | n | block | review | pass |
|---|---|---|---|---|
| `samples/` malicious (written for this repo) | 5 | 5 | 0 | 0 |
| `samples/` benign (written for this repo) | 2 | 0 | 0 | 2 |
| Skills in the official Claude plugin marketplace (149 files) | 33 | 0 | 10 | 23 |

Under `low_fp` the marketplace set is 0 / 5 / 28 and the samples are unchanged.

Read these for what they are. The malicious samples were written by the same hand as
the questions, so 5/5 says the pipeline works end to end, not that it catches skills
written by someone trying to evade it. The marketplace set is assumed benign, not
audited, and three of the questions were reworded after an earlier run on that same set
blocked 6 of 33 — so its numbers are tuned-on, not held-out. There is no recall
measurement on real malicious skills yet; that needs a labeled corpus, and it is the
first thing to add.

Two things the runs did show:

- **The verdict is sharper than the attribution.** On a malicious file many questions
  fire together (`review-assistant` scores above 0.9 on five traps, not all of which it
  contains). Trust `block`; treat the trap names as a pointer to where to look.
- **Structural alone is not enough.** `api-client-helper` splits its payload across two
  reference files and is clean to every detector; only the whole-skill pass catches it
  (`compositional_fragments` 0.88).

## Tuning

`skill_guard/traps.py` holds the questions, `skill_guard/policy.py` the action each trap
triggers and the thresholds. `strict` is the default because installing a skill is a
one-time decision with a person present: a false `review` costs a minute, a false
`pass` hands over the machine.

## Limits

- Text only. Images, PDFs, archives, and compiled binaries are checked for embedded
  instruction text and listed under `unscanned`; pixel-level steganography is out of
  reach.
- Static. It reads what is in the directory. A skill that downloads its real
  instructions at run time is flagged for doing so (`dynamic_cloaking`,
  `remote_execution`), but what it would download is never seen.
- Files longer than about 115k characters are scored on their first six chunks and
  marked as truncated.
- The scanner's own questions are sent alongside untrusted content. The state tells Jev
  that text addressed to the assessor is evidence, and `oversight_evasion` asks about
  it directly, but this has not been adversarially tested.
