"""Deterministic structural detectors, run alongside the semantic Jev questions.

Three jobs, all things a classifier reading for intent is bad at:

1. **Normalization.** Invisible Unicode, homoglyphs, and base64 hide a payload from a
   reviewer while the agent still reads it fine. They are stripped and decoded
   *before* the semantic call, so Jev scores the real instruction.
2. **The human/machine gap.** A skill's reviewer reads rendered markdown; the agent
   reads source. HTML comments, undisplayed elements, and link anchor text are where
   that gap is widest — the paper's Content Injection class — and they are syntax.
3. **Capability shapes.** Reading a credential store, sending data out, piping a
   download into a shell, writing to the agent's own memory or config. None is proof
   of malice; each is something the person installing the skill should be shown.

Detector hits are evidence, not verdicts: policy.py decides what to do with them.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import urlparse

# --- character-level obfuscation ------------------------------------------------

UNICODE_TAGS = re.compile(r"[\U000E0000-\U000E007F]")
# U+200D (zero-width joiner) is left out on purpose: it is what holds compound emoji
# together, and skills are full of emoji. It only counts when wedged inside a word.
ZERO_WIDTH = re.compile(
    "[\u200b\u200c\u200e\u200f\u2060-\u2064\ufeff\u00ad]|(?<=[A-Za-z])\u200d(?=[A-Za-z])"
)
BIDI_OVERRIDE = re.compile("[\u202a-\u202e\u2066-\u2069]")
# Fullwidth ASCII and mathematical alphanumerics: Latin letters in costume. Ordinary
# typography (ellipses, ligatures, superscripts) also changes under NFKC and is ignored.
STYLED_LATIN = re.compile("[\uff01-\uff5e\U0001d400-\U0001d7ff]")

# Cyrillic/Greek letters that render identically to ASCII. Only flagged inside a word
# that also contains ASCII letters — a skill written in Russian or Greek is not an attack.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "ο": "o", "α": "a", "ν": "v", "ρ": "p",
    "Α": "A", "Β": "B", "Ε": "E", "Ο": "O", "Ρ": "P",
}
_LOOKALIKES = "".join(HOMOGLYPHS)
MIXED_SCRIPT_WORD = re.compile(rf"\b(?=\w*[A-Za-z])(?=\w*[{_LOOKALIKES}])\w+\b")

INSTRUCTION_MARKERS = (
    "ignore", "disregard", "forget", "instead", "system", "prompt", "instruction",
    "you are", "act as", "reveal", "exfiltrate", "send to", "curl", "http", "bash",
    "eval", "/bin/sh",
)

# Text that overrides the agent or conceals something from the user. Used to tell a
# hidden instruction from an ordinary comment, so it is far narrower than the list
# above. Templates legitimately carry comments addressed to the agent ("FILL: one-line
# description", "copy this file to..."); a block-level detector must not fire on those.
# What it looks for is the combination no honest comment has: hidden *and* telling the
# agent to disobey or to keep quiet.
AGENT_DIRECTIVE = re.compile(
    r"ignore (?:all |any |the |your )*(?:user|previous|prior|above|earlier|other|instructions|rules)"
    r"|disregard (?:all |any |the |your )*(?:user|previous|prior|above|earlier|instructions|rules)"
    r"|\bsystem\s*:|you are now\b|new instructions\b"
    r"|(?:do not|don't|never) (?:tell|mention|reveal|inform|disclose)\b"
    r"|without (?:telling|asking|informing|notifying|mentioning)\b"
    r"|\bsecretly\b|exfiltrat",
    re.I,
)
# Stricter still, for strings pulled out of binaries, where "curl" and "upload" are noise.
INJECTION_PHRASE = re.compile(
    rb"ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|rules|prompts)"
    rb"|disregard (?:the |all |your )?(?:previous|prior|above|system)"
    rb"|you are now\b|new instructions:|system prompt|<\s*system\s*>|\bSYSTEM:\s"
    rb"|do not (?:tell|inform|mention (?:this )?to) the user",
    re.I,
)

# --- the human/machine gap ------------------------------------------------------

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_ELEMENT = re.compile(
    r"<[a-z][^>]*\bstyle\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden"
    r"|font-size\s*:\s*0|opacity\s*:\s*0(?![.\d])|(?:left|top)\s*:\s*-\d{3,}"
    r"|color\s*:\s*(?:#fff(?:fff)?\b|white))[^\"']*[\"'][^>]*>([^<]{8,})",
    re.I,
)
LATEX_HIDDEN = re.compile(r"\\(?:textcolor|color)\{white\}|\\tiny\b|\\fontsize\{0", re.I)

MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*([^)\s]+)")
MD_LINK = re.compile(r"(?<!!)\[([^\]]+)\]\(\s*([^)\s]+)")
HTML_SRC = re.compile(r"<(?:img|script|iframe)[^>]*\b(?:src|href)\s*=\s*[\"']([^\"']+)", re.I)
BARE_URL = re.compile(r"(?:https?|ftp)://[^\s<>\"')\]`]+", re.I)
RAW_IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LOOKS_LIKE_HOST = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)", re.I)
# A placeholder the agent is meant to fill in: ${VAR}, $VAR, {name}, {{name}}, <name>, $(cmd).
INTERPOLATION = re.compile(r"\$\{?[A-Za-z_]|\$\(|\{\{?\s*[A-Za-z_]|<[A-Za-z_][A-Za-z_ ]*>|%s")

# --- secrets --------------------------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "openai_key": re.compile(r"\bsk-(?:or-v1-|proj-|ant-)?[A-Za-z0-9_-]{20,}"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    "google_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
}

# --- URLs -----------------------------------------------------------------------

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "shorte.st",
}
RISKY_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq"}
URL_CREDENTIALS = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@", re.I)
# Request catchers, paste sites, tunnels, and chat webhooks: places built to receive
# arbitrary data from anywhere. Legitimate in a skill about exactly that service.
EXFIL_SINKS = (
    "webhook.site", "requestbin.com", "pipedream.net", "ngrok.io", "ngrok.app",
    "ngrok-free.app", "trycloudflare.com", "loca.lt", "serveo.net", "burpcollaborator.net",
    "interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site", "pastebin.com",
    "transfer.sh", "0x0.st", "hastebin.com", "discord.com/api/webhooks",
    "discordapp.com/api/webhooks", "hooks.slack.com", "api.telegram.org/bot",
)

# --- capability shapes ----------------------------------------------------------

REMOTE_EXECUTION = re.compile(
    r"(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby)\b"
    r"|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b"
    r"|\beval\s+[\"']?\$\(\s*(?:curl|wget)\b"
    r"|\bexec\s*\([^)\n]*(?:urlopen|requests\.get|httpx\.get)"
    r"|\b(?:iex|Invoke-Expression)\b[^\n]*(?:DownloadString|Invoke-WebRequest|\biwr\b)",
    re.I,
)
OBFUSCATED_EXEC = re.compile(
    r"\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.b64decode|bytes\.fromhex|codecs\.decode|zlib\.decompress|marshal\.loads|atob)\b"
    r"|\bbase64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"
    r"|\beval\s*\(\s*atob\s*\(",
    re.I,
)
CREDENTIAL_ACCESS = re.compile(
    r"\.ssh/(?:id_|authorized_keys|config|known_hosts)|\bid_(?:rsa|ed25519|ecdsa)\b"
    r"|\.aws/(?:credentials|config)|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials"
    r"|\.docker/config\.json|\.kube/config|gcloud/(?:credentials|application_default|access_tokens)"
    r"|security\s+find-(?:generic|internet)-password|login\.keychain|Login Data\b|cookies\.sqlite"
    r"|\bgh\s+auth\s+token\b|\.claude/\.credentials|\.(?:bash|zsh)_history"
    r"|/etc/shadow\b|\bcat\s+[^\n|;]*\.env\b|\bprintenv\b"
    r"|json\.dumps\(\s*(?:dict\(\s*)?os\.environ|JSON\.stringify\(\s*process\.env\s*[,)]"
    r"|Object\.(?:entries|keys)\(\s*process\.env\s*\)",
    re.I,
)
OUTBOUND_SEND = re.compile(
    r"\bcurl\b[^\n]*\s(?:-d|--data\S*|-F|--form|-T|--upload-file|-X\s*(?:POST|PUT))\b"
    r"|\bwget\b[^\n]*--post-(?:data|file)|\b(?:requests|httpx|session)\.(?:post|put)\s*\("
    r"|urlopen\s*\([^)\n]*data\s*=|method\s*[:=]\s*[\"'](?:POST|PUT)[\"']"
    r"|\bnc\s+(?:-\S+\s+)*\S+\s+\d{2,5}\b|\bscp\s|\bsmtplib\b|\.sendall\s*\(|\bInvoke-RestMethod\b",
    re.I,
)
_PERSISTENT = (
    r"CLAUDE\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md|copilot-instructions\.md|\.cursorrules|\.cursor/rules"
    r"|\.claude/(?:settings(?:\.local)?\.json|hooks|skills|agents|commands|projects)"
    r"|\.mcp\.json|claude_desktop_config|\.(?:bash|zsh)rc\b|\.(?:bash_|z)profile\b|\.zshenv\b"
    r"|\bcrontab\b|LaunchAgents|\.git/hooks"
)
# Only verbs that unambiguously mean "put text into": "update", "add", and "create" sit
# next to these filenames in every plugin-development guide. Softer phrasings are the
# semantic pass's job (memory_poisoning).
_WRITE = r">>|\btee\b|\bcat\s*>|\b(?:write|append|insert|echo)\b"
PERSISTENCE_TARGET = re.compile(
    # The verb and the target are often on adjacent lines of wrapped prose: allow one break.
    rf"(?:{_WRITE})[^\n]{{0,80}}\n?[^\n]{{0,40}}(?:{_PERSISTENT})|(?:{_PERSISTENT})[^\n]{{0,60}}(?:>>|\bappend\b)",
    re.I,
)
PERMISSION_BYPASS = re.compile(
    r"--dangerously-skip-permissions|bypassPermissions|dangerouslyDisableSandbox|--allow-all-tools|--yolo\b"
    r"|--no-verify\b|chmod\s+(?:-R\s+)?0?777\b|spctl\s+--master-disable|csrutil\s+disable"
    r"|xattr\s+-\w*d\w*\s+com\.apple\.quarantine|Set-ExecutionPolicy\s+Bypass"
    r"|\bcurl\b[^\n]*\s(?:-k|--insecure)\b|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"
    r"|StrictHostKeyChecking[= ]no",
    re.I,
)

EXECUTABLE_MAGIC = (
    b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
)


@dataclass
class DetectorHit:
    name: str
    detail: str


def _clip(text: str, limit: int = 120) -> str:
    return repr(" ".join(text.split())[:limit])


def _decode_b64_blobs(text: str) -> list[str]:
    """Return decoded text for base64 blobs that decode to readable instruction-like text."""
    decoded = []
    for blob in re.findall(r"[A-Za-z0-9+/]{32,}={0,2}", text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() or c.isspace() for c in candidate) < len(candidate) * 0.9:
            continue
        if any(marker in candidate.lower() for marker in INSTRUCTION_MARKERS) or AGENT_DIRECTIVE.search(candidate):
            decoded.append(candidate)
    return decoded


def normalize(text: str) -> tuple[str, list[DetectorHit]]:
    """Strip obfuscation and surface what was stripped.

    Returns the de-obfuscated text to send to Jev, plus a hit per evasion technique
    found. Decoded payloads are appended so the semantic pass scores them too.
    """
    hits: list[DetectorHit] = []
    text = text.removeprefix("\ufeff")  # a leading byte-order mark is an editor artefact

    if tags := UNICODE_TAGS.findall(text):
        smuggled = "".join(chr(ord(c) - 0xE0000) for c in tags if 0xE0020 <= ord(c) <= 0xE007E)
        hits.append(DetectorHit("invisible_unicode", f"{len(tags)} Unicode tag chars: {smuggled[:120]!r}"))
        text = UNICODE_TAGS.sub("", text) + (f"\n[decoded hidden text: {smuggled}]" if smuggled else "")

    if zw := ZERO_WIDTH.findall(text):
        hits.append(DetectorHit("invisible_unicode", f"{len(zw)} zero-width/invisible chars"))
        text = ZERO_WIDTH.sub("", text)

    if BIDI_OVERRIDE.search(text):
        hits.append(DetectorHit("invisible_unicode", "bidirectional text override characters"))
        text = BIDI_OVERRIDE.sub("", text)

    if mixed := MIXED_SCRIPT_WORD.findall(text):
        hits.append(DetectorHit("homoglyphs", f"{len(mixed)} mixed-script words, e.g. {mixed[0]!r}"))
        text = MIXED_SCRIPT_WORD.sub(lambda m: "".join(HOMOGLYPHS.get(c, c) for c in m.group()), text)

    if styled := STYLED_LATIN.findall(text):
        import unicodedata

        hits.append(DetectorHit("unicode_variants", f"{len(styled)} fullwidth/mathematical Latin chars"))
        text = STYLED_LATIN.sub(lambda m: unicodedata.normalize("NFKC", m.group()), text)

    for payload in _decode_b64_blobs(text):
        hits.append(DetectorHit("encoded_payload", f"base64 decodes to instructions: {payload[:120]!r}"))
        text += f"\n[decoded base64: {payload}]"

    return text, hits


def find_hidden_markup(text: str) -> list[DetectorHit]:
    """Directions to the agent that a human reading the rendered file would not see."""
    hits = []
    for comment in HTML_COMMENT.findall(text):
        if AGENT_DIRECTIVE.search(comment):
            hits.append(DetectorHit("hidden_markup", f"HTML comment addresses the agent: {_clip(comment)}"))
    for hidden in HIDDEN_ELEMENT.findall(text):
        if AGENT_DIRECTIVE.search(hidden):
            hits.append(DetectorHit("hidden_markup", f"undisplayed element addresses the agent: {_clip(hidden)}"))
    for match in LATEX_HIDDEN.finditer(text):
        following = text[match.end() : match.end() + 240]
        if AGENT_DIRECTIVE.search(following):
            hits.append(DetectorHit("hidden_markup", f"white/tiny LaTeX text addresses the agent: {_clip(following)}"))
    return hits


def find_masked_links(text: str) -> list[DetectorHit]:
    """Formatting syntax used as a disguise: the paper's syntactic masking."""
    hits = []
    for anchor, url in MD_LINK.findall(text) + MD_IMAGE.findall(text):
        if AGENT_DIRECTIVE.search(anchor) and len(anchor.split()) >= 3:
            hits.append(DetectorHit("masked_link", f"link/alt text carries an instruction: {_clip(anchor)}"))
        shown, actual = LOOKS_LIKE_HOST.match(anchor.strip()), (urlparse(url).hostname or "").lower()
        if shown and actual:
            shown_host = shown.group(1).lower().removeprefix("www.")
            if not (actual.removeprefix("www.") == shown_host or actual.endswith("." + shown_host)):
                hits.append(DetectorHit("masked_link", f"link text shows {shown_host} but goes to {actual}"))
    return hits


def find_exfiltration_channels(text: str) -> list[DetectorHit]:
    """Outbound URLs with a slot for the agent to fill in.

    In live traffic the tell is a URL already carrying data. In a skill the data is
    not there yet — what is there is the template: an absolute URL whose query string
    contains a placeholder. An image or tag is the high-value case, because rendering
    it sends the request with no further action from anyone.
    """
    hits = []
    for urls, kind, auto in (
        ([url for _, url in MD_IMAGE.findall(text)], "markdown image", True),
        (HTML_SRC.findall(text), "html tag", True),
        ([url for _, url in MD_LINK.findall(text)], "markdown link", False),
    ):
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                continue
            if INTERPOLATION.search(parsed.query):
                name = "exfiltration_channel" if auto else "data_bearing_link"
                prefix = "auto-fetched " if auto else ""
                hits.append(DetectorHit(name, f"{prefix}{kind} to {parsed.hostname} with a filled-in query: {url[:100]}"))
    return hits


def find_secrets(text: str) -> list[DetectorHit]:
    """Credentials shipped inside the skill — the author's mistake, or bait."""
    hits = []
    for name, pattern in SECRET_PATTERNS.items():
        if matches := pattern.findall(text):
            hits.append(DetectorHit("embedded_secret", f"{name} ({len(matches)} match)"))
    return hits


def find_risky_urls(text: str) -> list[DetectorHit]:
    """Addresses that are suspicious on their face, independent of surrounding intent."""
    hits = []
    if URL_CREDENTIALS.search(text):
        hits.append(DetectorHit("risky_url", "credentials embedded in URL"))
    seen: set[str] = set()
    for url in BARE_URL.findall(text):
        host = (urlparse(url).hostname or "").lower()
        if not host:
            continue
        for sink in EXFIL_SINKS:
            domain, _, path = sink.partition("/")
            if sink not in seen and (host == domain or host.endswith("." + domain)) and f"/{path}" in url:
                seen.add(sink)
                hits.append(DetectorHit("exfil_sink", f"data-collection endpoint {sink}"))
        if host in seen:
            continue
        seen.add(host)
        if RAW_IP_HOST.match(host) and not host.startswith(("127.", "0.")):
            hits.append(DetectorHit("risky_url", f"raw IP host {host}"))
        if host.startswith("xn--") or ".xn--" in host:
            hits.append(DetectorHit("risky_url", f"punycode/IDN homograph domain {host}"))
        if host in SHORTENERS:
            hits.append(DetectorHit("risky_url", f"link shortener {host} hides destination"))
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            hits.append(DetectorHit("risky_url", f"high-abuse TLD .{host.rsplit('.', 1)[-1]}"))
    return hits


def find_capabilities(text: str, kind: str) -> list[DetectorHit]:
    """What the file reaches for: credentials, the network, persistence, safeguards."""
    hits = []
    for name, pattern, label in (
        ("remote_execution", REMOTE_EXECUTION, "downloads and executes"),
        ("obfuscated_exec", OBFUSCATED_EXEC, "executes a decoded blob"),
        ("credential_access", CREDENTIAL_ACCESS, "reads a credential store"),
        ("persistence_target", PERSISTENCE_TARGET, "writes to agent memory/config or startup files"),
        ("permission_bypass", PERMISSION_BYPASS, "disables a safeguard"),
    ):
        if match := pattern.search(text):
            hits.append(DetectorHit(name, f"{label}: {_clip(match.group(), 90)}"))
    # Co-occurrence is only treated as a flow in a script, where both halves execute.
    # In prose, a security guide can mention ~/.ssh and `curl -d` without doing either.
    if kind == "code" and (cred := CREDENTIAL_ACCESS.search(text)) and (send := OUTBOUND_SEND.search(text)):
        hits.append(
            DetectorHit("exfiltration_flow", f"reads {_clip(cred.group(), 40)} and sends via {_clip(send.group(), 60)}")
        )
    return hits


def scan(text: str, kind: str = "instructions") -> tuple[str, list[DetectorHit]]:
    """Normalize one text file and return it alongside every structural hit found.

    Everything after normalization runs on the de-obfuscated text, so an encoded
    payload is checked after decoding, not before.
    """
    normalized, hits = normalize(text)
    hits += find_hidden_markup(normalized)
    hits += find_masked_links(normalized)
    hits += find_exfiltration_channels(normalized)
    hits += find_secrets(normalized)
    hits += find_risky_urls(normalized)
    hits += find_capabilities(normalized, kind)
    return normalized, hits


def scan_binary(raw: bytes) -> list[DetectorHit]:
    """The little that can be said about a file the text model cannot read.

    This is not steganalysis. It catches the cheap version — instruction text sitting
    in metadata or appended after the image ends — and is honest that pixel-level
    payloads are out of reach; scan.py lists every binary as unscanned for that reason.
    """
    hits = []
    if raw.startswith(EXECUTABLE_MAGIC):
        hits.append(DetectorHit("opaque_binary", "compiled executable — behaviour cannot be reviewed"))
    if match := INJECTION_PHRASE.search(raw):
        context = raw[max(0, match.start() - 20) : match.end() + 80].decode("latin-1")
        hits.append(DetectorHit("media_payload", f"instruction text inside binary: {_clip(context)}"))
    if raw.startswith(b"\x89PNG") and (end := raw.rfind(b"IEND")) != -1 and len(raw) - (end + 8) > 16:
        hits.append(DetectorHit("media_trailer", f"{len(raw) - end - 8} bytes appended after the end of the PNG"))
    return hits
