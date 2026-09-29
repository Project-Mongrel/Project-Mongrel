"""Small shared conversational normalization primitives."""

from dataclasses import dataclass
import re
from collections.abc import Sequence


History = Sequence[tuple[str, str]]

_CASUAL_ALIASES = (
    (re.compile(r"\b(?:vulnerabilty|vunerability|vuln)\b"), "vulnerability"),
    (re.compile(r"\bexploitible\b"), "exploitable"),
    (re.compile(r"\bonw\b"), "one"),
    (re.compile(r"\b(?:elobarate|elaborat)\b"), "elaborate"),
    (re.compile(r"\bsecind\b"), "second"),
    (re.compile(r"\bwouldnt\b"), "wouldn't"),
    (re.compile(r"\bdont\b"), "don't"),
    (re.compile(r"\bwat\b"), "what"),
    (re.compile(r"\bnxt\b"), "next"),
)
_CASUAL_FILLERS = (
    re.compile(r"\b(?:the\s+)?fuck(?:ing)?\b"),
    re.compile(r"\bactually\b"),
    re.compile(r"\bso\b"),
    re.compile(r"\bok(?:ay)?\b"),
    re.compile(r"\bplease\b"),
    re.compile(r"\bjust\b"),
)
_TECHNICAL_TOKEN_PATTERNS = (
    re.compile(r"https?://[^\s<>]+", re.IGNORECASE),
    re.compile(r"(?<![\w])/(?:[^\s/]+/)*[^\s]+"),
    re.compile(r"(?<![\w])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.]+"),
    re.compile(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?"),
    re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    re.compile(r"\bport\s+\d{1,5}\b", re.IGNORECASE),
    re.compile(r"(?<![\w])[A-Za-z][\w.-]*:[A-Za-z][\w.-]*(?![\w])"),
    re.compile(r"(?<![\w])(?:[A-Za-z][\w.-]*)\s+-[A-Za-z0-9][^\s]*"),
    re.compile(r"(?<![\w])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{1,5})?(?:/[^\s]*)?"),
)
_TECHNICAL_CONTEXT_WORDS = {
    "can", "could", "does", "do", "will", "would", "should", "run", "use", "support", "supported",
    "recommend", "have", "has", "what", "which", "tool", "tools", "mongrel", "please", "the", "a", "an",
    "for", "with", "in", "on", "as", "my", "this", "that", "it", "first", "next", "now", "is", "right",
}


@dataclass(frozen=True)
class ConversationUnderstanding:
    original_text: str
    normalized_text: str
    is_follow_up: bool
    requests_detail: bool
    narrows_selection: bool
    referenced_ordinal: int | None
    previous_assistant_text: str
    previous_assistant_texts: tuple[str, ...]
    previous_user_text: str


def normalize_conversational_text(text: str) -> str:
    """Normalize conversational noise while preserving technical token characters."""

    normalized = " ".join(str(text or "").lower().replace("’", "'").split())
    for pattern, replacement in _CASUAL_ALIASES:
        normalized = pattern.sub(replacement, normalized)
    for pattern in _CASUAL_FILLERS:
        normalized = pattern.sub(" ", normalized)
    return " ".join(normalized.split())


def extract_technical_tokens(text: str) -> tuple[str, ...]:
    """Extract complete opaque technical values without interpreting their meaning."""

    source = str(text or "")
    matches: list[tuple[int, int, str]] = []
    for pattern in _TECHNICAL_TOKEN_PATTERNS:
        for match in pattern.finditer(source):
            value = match.group(0).rstrip(".,;!?)]}")
            if value:
                matches.append((match.start(), match.end(), value))
    selected: list[tuple[int, int, str]] = []
    for start, end, value in sorted(matches, key=lambda item: (item[0], -(item[1] - item[0]))):
        if any(start < chosen_end and end > chosen_start for chosen_start, chosen_end, _ in selected):
            continue
        selected.append((start, end, value))

    tokens = [value for _start, _end, value in selected]
    for word_match in re.finditer(r"(?<![\w])([A-Za-z][A-Za-z0-9_.-]{2,})(?![\w])", source):
        word = word_match.group(1)
        if any(
            word_match.start() < chosen_end and word_match.end() > chosen_start
            for chosen_start, chosen_end, _ in selected
        ):
            continue
        if word.lower() not in _TECHNICAL_CONTEXT_WORDS and word not in tokens:
            tokens.append(word)
    return tuple(tokens)


def understand_conversation(text: str, history: History = ()) -> ConversationUnderstanding:
    original = str(text or "").strip()
    normalized = normalize_conversational_text(original)
    prior_assistant = ""
    prior_assistants = []
    prior_user = ""
    for role, content in reversed(history):
        if str(role).lower() == "assistant":
            assistant_text = str(content or "")
            if not prior_assistant:
                prior_assistant = assistant_text
            if len(prior_assistants) < 4:
                prior_assistants.append(assistant_text)
        elif str(role).lower() == "user" and not prior_user:
            prior_user = str(content or "")
    intent_text = re.sub(r"[?!.,;:]+", " ", normalized)
    intent_text = " ".join(intent_text.split())
    requests_detail = bool(re.search(r"\b(?:elaborate|expand|go deeper|explain|why|what do you mean)\b", intent_text))
    narrows_selection = bool(
        re.search(r"\b(?:which|what)\s+(?:one|tool)\b|\b(?:first|second|third|after that|why that one)\b|\bwhat about\b", intent_text)
    )
    referenced_ordinal = None
    ordinal_match = re.search(r"\b(first|second|third|two|three)\b", intent_text)
    if ordinal_match:
        referenced_ordinal = {"first": 1, "one": 1, "second": 2, "two": 2, "third": 3, "three": 3}[ordinal_match.group(1)]
    is_follow_up = bool(prior_assistant) and (
        requests_detail
        or narrows_selection
        or len(intent_text.split()) <= 8
        or bool(re.search(r"\b(?:that|this|it|the above)\b", intent_text))
    )
    return ConversationUnderstanding(
        original_text=original,
        normalized_text=normalized,
        is_follow_up=is_follow_up,
        requests_detail=requests_detail,
        narrows_selection=narrows_selection,
        referenced_ordinal=referenced_ordinal,
        previous_assistant_text=prior_assistant,
        previous_assistant_texts=tuple(prior_assistants),
        previous_user_text=prior_user,
    )
