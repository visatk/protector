"""Deep Unicode normalizer, homoglyph folder, obfuscation detector, and PII redactor."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Invisible / zero-width / formatting characters commonly abused to break regex filters
INVISIBLE_CHARS = frozenset(
    {
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER (careful: legitimate in Bengali/Indic scripts!)
        "\u200d",  # ZERO WIDTH JOINER (legitimate in Bengali/emoji!)
        "\u2060",  # WORD JOINER
        "\ufeff",  # BOM / ZERO WIDTH NO-BREAK SPACE
        "\u00ad",  # SOFT HYPHEN
        "\u034f",  # COMBINING GRAPHEME JOINER
        "\u180e",  # MONGOLIAN VOWEL SEPARATOR
        "\u200e",  # LEFT-TO-RIGHT MARK
        "\u200f",  # RIGHT-TO-LEFT MARK
        "\u202a",  # LRE
        "\u202b",  # RLE
        "\u202c",  # PDF
        "\u202d",  # LRO
        "\u202e",  # RLO (dangerous file-name & text spoofing!)
        "\u2066",  # LRI
        "\u2067",  # RLI
        "\u2068",  # FSI
        "\u2069",  # PDI
    }
)

BIDI_OVERRIDE_CHARS = frozenset({"\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"})
PURE_OBFUSCATION_INVISIBLES = frozenset({"\u200b", "\u2060", "\ufeff", "\u00ad", "\u034f"})

# Cyrillic & Greek visual confusables mapped to Latin equivalents
HOMOGLYPH_MAP = str.maketrans(
    {
        # Cyrillic lowercase
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
        "к": "k", "м": "m", "т": "t", "н": "h", "в": "b",
        # Cyrillic uppercase
        "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y", "Х": "X",
        "І": "I", "Ј": "J", "Ѕ": "S", "К": "K", "М": "M", "Т": "T", "Н": "H", "В": "B",
        # Greek confusables
        "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
        "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
        "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    }
)

# Leetspeak mapping used for secondary obfuscation scan
LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)

_RE_MULTI_SPACE = re.compile(r"\s+")
_RE_DOT_SPACED_WORD = re.compile(r"(?<!\w)(?:[a-zA-Z][\s._\-*]){3,}[a-zA-Z](?!\w)")
_RE_LATIN = re.compile(r"[A-Za-z]")
_RE_CYRILLIC_GREEK = re.compile(r"[\u0400-\u04FF\u0370-\u03FF]")
_RE_BENGALI = re.compile(r"[\u0980-\u09FF]")
_RE_MATH_STYLED = re.compile(r"[\U0001D400-\U0001D7FF]")

# Privacy-preserving PII redaction regexes (used before audit logging or optional external AI calls)
_RE_INTL_PHONE = re.compile(r"\+\d{1,3}[\s.-]?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}")
_RE_CARD = re.compile(r"(?<!\+)\b(?:\d[ -]?){13,19}\b")
_RE_PHONE = re.compile(r"(?<!\d)(?:\(?\d{3,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}(?!\d)")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


@dataclass(slots=True)
class NormalizedText:
    """Result of deep text normalization + evasion telemetry."""

    original: str
    cleaned: str              # Preserves Bengali/Unicode scripts while removing pure zero-width abuse
    folded_ascii: str         # Lowercased NFKC + homoglyph-folded Latin/mixed text
    deobfuscated: str         # Aggressive leetspeak + spaced-letter unfolded form
    invisible_count: int = 0
    bidi_override_count: int = 0
    mixed_script_tokens: int = 0
    styled_unicode_count: int = 0
    spaced_evasion_count: int = 0

    @property
    def obfuscation_score(self) -> int:
        """Compute 0..60 anomaly score purely from anti-filter evasion tricks."""
        score = 0
        if self.bidi_override_count > 0:
            score += 35  # RTL override is almost exclusively used for filename/URL spoofing
        if self.invisible_count >= 3:
            score += min(30, 10 + self.invisible_count * 3)
        if self.mixed_script_tokens >= 1:
            score += min(35, 18 + self.mixed_script_tokens * 8)
        if self.styled_unicode_count >= 8:
            score += 12
        if self.spaced_evasion_count >= 1:
            score += min(25, self.spaced_evasion_count * 12)
        return min(60, score)


def _count_mixed_script_tokens(text: str) -> int:
    """Detect tokens mixing Latin with Cyrillic/Greek (classic homoglyph spoofing)."""
    mixed = 0
    for token in re.findall(r"\S+", text):
        if _RE_LATIN.search(token) and _RE_CYRILLIC_GREEK.search(token):
            mixed += 1
    return mixed


def _collapse_spaced_words(text: str) -> str:
    """Turn 'f.r.e.e c r y p t o' -> 'free crypto' for secondary policy matching."""

    def _repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        return re.sub(r"[\s._\-*]+", "", raw)

    return _RE_DOT_SPACED_WORD.sub(_repl, text)


def normalize_text(text: str) -> NormalizedText:
    """Normalize incoming text while extracting evasion telemetry.

    Carefully preserves legitimate Bengali/Indic ZWJ/ZWNJ joiners unless used inside Latin tokens.
    """
    if not text:
        return NormalizedText(original="", cleaned="", folded_ascii="", deobfuscated="")

    bidi_count = sum(1 for ch in text if ch in BIDI_OVERRIDE_CHARS)
    styled_count = len(_RE_MATH_STYLED.findall(text))
    has_bengali = bool(_RE_BENGALI.search(text))

    # Count pure obfuscation invisible characters (avoid penalizing legitimate Bengali ZWNJ/ZWJ)
    pure_inv = sum(1 for ch in text if ch in PURE_OBFUSCATION_INVISIBLES)
    if not has_bengali:
        pure_inv += sum(1 for ch in text if ch in {"\u200c", "\u200d"})

    # Strip pure obfuscation invisibles and BiDi overrides for clean text
    strip_set = BIDI_OVERRIDE_CHARS | PURE_OBFUSCATION_INVISIBLES | {"\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u180e"}
    if not has_bengali:
        strip_set = strip_set | {"\u200c", "\u200d"}

    cleaned = "".join(ch for ch in text if ch not in strip_set)
    cleaned = _RE_MULTI_SPACE.sub(" ", cleaned).strip()

    # NFKC normalization unfolds mathematical bold/italic/fullwidth characters
    nfkc = unicodedata.normalize("NFKC", cleaned)

    # Detect mixed-script homoglyph tokens BEFORE folding Cyrillic/Greek -> Latin
    mixed_tokens = _count_mixed_script_tokens(nfkc)

    # Fold homoglyphs into Latin lowercase
    folded = nfkc.translate(HOMOGLYPH_MAP).lower()
    # Also remove any combining diacritical marks used as Zalgo/evasion on Latin text
    if not has_bengali:
        decomposed = unicodedata.normalize("NFD", folded)
        folded = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    folded = _RE_MULTI_SPACE.sub(" ", folded).strip()

    # Secondary deobfuscated text: collapse spaced letters and unfold leetspeak
    spaced_matches = _RE_DOT_SPACED_WORD.findall(folded)
    deobf = _collapse_spaced_words(folded)
    # Apply leetspeak unfolding only to alphanumeric tokens that already contain at least one Latin letter
    deobf_tokens: list[str] = []
    for tok in deobf.split():
        if _RE_LATIN.search(tok):
            deobf_tokens.append(tok.translate(LEET_MAP))
        else:
            deobf_tokens.append(tok)
    deobf_final = " ".join(deobf_tokens)

    return NormalizedText(
        original=text,
        cleaned=cleaned,
        folded_ascii=folded,
        deobfuscated=deobf_final,
        invisible_count=pure_inv,
        bidi_override_count=bidi_count,
        mixed_script_tokens=mixed_tokens,
        styled_unicode_count=styled_count,
        spaced_evasion_count=len(spaced_matches),
    )


def redact_pii(text: str, max_len: int = 180) -> str:
    """Redact emails, phone numbers, and card-like digit sequences for privacy-safe logs."""
    if not text:
        return ""
    redacted = _RE_EMAIL.sub("[REDACTED_EMAIL]", text)
    redacted = _RE_INTL_PHONE.sub("[REDACTED_PHONE]", redacted)
    redacted = _RE_CARD.sub("[REDACTED_CARD]", redacted)
    redacted = _RE_PHONE.sub("[REDACTED_PHONE]", redacted)
    redacted = _RE_MULTI_SPACE.sub(" ", redacted).strip()
    if len(redacted) > max_len:
        return redacted[:max_len] + "..."
    return redacted
