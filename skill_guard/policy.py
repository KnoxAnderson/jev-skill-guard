"""Turn a skill's assessment into an install decision. Thresholds live here, in code you
can read and tune against skills you have labeled yourself, not in a system prompt."""

from typing import Any

# A high-probability trap triggers the action below. `block` is reserved for traps
# whose worst case is a compromise; the rest are judgment calls a person should make,
# because legitimate skills sit close to them (a vendor's own skill recommends the
# vendor; a memory skill writes memory).
TRAP_ACTION = {
    "hidden_instructions": "block",
    "syntactic_masking": "block",
    "dynamic_cloaking": "block",
    "oversight_evasion": "block",
    "memory_poisoning": "block",
    "embedded_jailbreak": "block",
    "data_exfiltration": "block",
    "subagent_spawning": "block",
    "self_propagation": "block",
    "overseer_deception": "block",
    "compositional_fragments": "block",
    "covert_behaviour": "block",
    "unauthorized_action": "block",
    "scope_mismatch": "review",
    "privilege_overreach": "review",
    "biased_framing": "review",
    "persona_hyperstition": "review",
    "knowledge_poisoning": "review",
    "contextual_learning": "review",
    "sybil_identities": "review",
}

# Per-trap thresholds, for the cases where the uniform bar is the wrong call.
TRAP_THRESHOLD = {
    # A skill that ships data out is the worst case and a second look is cheap.
    "data_exfiltration": {"review": 0.20, "action": 0.60},
}

# Structural detector hits carry their own action, independent of any probability.
# They fire on syntax, so a skill cannot talk the model out of them.
STRUCTURAL_ACTION = {
    "invisible_unicode": "block",  # no legitimate skill hides text from its reviewer
    "encoded_payload": "block",  # base64 that decodes to instructions is never incidental
    "hidden_markup": "block",  # instructions inside a comment or an undisplayed element
    "exfiltration_channel": "block",  # auto-fetched URL built from interpolated data
    "exfiltration_flow": "block",  # a script that reads credentials and sends something out
    "media_payload": "block",  # instruction text inside an image or other binary
    "obfuscated_exec": "block",  # exec() of a decoded blob has no innocent reading in a skill
    "masked_link": "review",
    "data_bearing_link": "review",
    "homoglyphs": "review",
    "unicode_variants": "review",
    "embedded_secret": "review",
    "risky_url": "review",
    "exfil_sink": "review",  # request catchers, paste sites, tunnels
    "remote_execution": "review",  # curl | sh — common in install docs, still worth a look
    "credential_access": "review",
    "persistence_target": "review",  # touches agent memory/config or shell startup
    "permission_bypass": "review",
    "media_trailer": "review",  # bytes appended after the end of an image
    "opaque_binary": "review",  # a compiled executable nobody can read
    "scan_error": "review",  # could not be assessed, so it is not cleared
}

PRECEDENCE = ["block", "review", "pass"]  # highest precedence wins

POLICIES: dict[str, dict[str, float]] = {
    "strict": {"review_threshold": 0.35, "action_threshold": 0.70, "severity_block": 2.0},
    "low_fp": {"review_threshold": 0.60, "action_threshold": 0.85, "severity_block": 2.5},
}
# Installing a skill is a one-time decision with a person present, so a false `review`
# costs a minute; a false `pass` hands over the machine. Hence strict, where jev-guard
# (screening live traffic) defaults to low_fp. Neither is tuned on labeled skills yet.
DEFAULT_POLICY = "strict"


def triggered(nouls: dict[str, float], policy: dict[str, float]) -> list[dict[str, Any]]:
    """Every trap at or above its review threshold, most probable first."""
    found = []
    for trap, probability in nouls.items():
        override = TRAP_THRESHOLD.get(trap)
        action_at = override["action"] if override else policy["action_threshold"]
        review_at = override["review"] if override else policy["review_threshold"]
        if probability >= action_at:
            found.append({"trap": trap, "probability": probability, "action": TRAP_ACTION[trap]})
        elif probability >= review_at:
            found.append({"trap": trap, "probability": probability, "action": "review"})
    return sorted(found, key=lambda f: -f["probability"])


def worst(actions: list[str]) -> str:
    return next((action for action in PRECEDENCE if action in actions), "pass")


def route(
    nouls: dict[str, float],
    severity: float,
    policy: dict[str, float],
    structural: list[dict[str, Any]] | None = None,
) -> str:
    """Turn one file's (or the whole skill's) assessment into one action."""
    actions = [finding["action"] for finding in triggered(nouls, policy)]
    if severity >= policy["severity_block"]:
        actions = ["block" if action == "review" else action for action in actions]
    # Structural hits are added after the severity rewrite so they keep their own
    # action regardless of how harmless the model judged the file to be.
    for hit in structural or []:
        actions.append(STRUCTURAL_ACTION.get(hit["name"], "review"))
    return worst(actions)
