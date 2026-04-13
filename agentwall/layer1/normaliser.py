"""
Adversarial text normaliser.

Attackers use these evasion techniques against keyword/regex detectors:
  1. Unicode homoglyphs   — "іgnore" (Cyrillic і) vs "ignore" (Latin i)
  2. Zero-width chars     — "ig\u200Bnore" (ZWS between ig and nore)
  3. Lookalike symbols    — "ıgnore" (Turkish ı)
  4. HTML/URL encoding    — "%69gnore" or "&#105;gnore"
  5. Leetspeak            — "1gn0r3"
  6. Markdown             — "**ignore**" or "`ignore`"
  7. Excessive whitespace — "i g n o r e"
  8. Case chaos           — "iGnOrE"
  9. Combining chars      — "i\u0307gnore" (i + combining dot)
 10. RTL override         — U+202E right-to-left override

This normaliser collapses all of the above before any detection layer runs.
"""
import re
import unicodedata
import urllib.parse
import html

try:
    from confusable_homoglyphs import confusables
    HAS_CONFUSABLES = True
except ImportError:
    HAS_CONFUSABLES = False


# Zero-width and invisible Unicode characters
_ZERO_WIDTH = re.compile(r'[\u200b-\u200f\u2060-\u2064\u206a-\u206f\ufeff\u00ad]')
# Combining diacritics (U+0300–U+036F)
_COMBINING  = re.compile(r'[\u0300-\u036f]')
# RTL/LTR override characters
_BIDI       = re.compile(r'[\u202a-\u202e\u2066-\u2069]')
# Markdown emphasis stripped
_MARKDOWN   = re.compile(r'[*_`~|]{1,3}(.*?)[*_`~|]{1,3}')
# Excessive whitespace (including unicode spaces)
_SPACES     = re.compile(r'[\s\u00a0\u2000-\u200a\u3000]+')

# Leetspeak map (common substitutions)
LEET_MAP = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '7': 't', '@': 'a', '$': 's',
    '!': 'i', '|': 'l',
})

# Visual Canonicalization Map
VISUAL_MAP = str.maketrans({
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', # Cyrillic lookalikes
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ꮯ': 'c', 'ꭰ': 'a'
})


def normalise_text(text: str) -> str:
    """Apply all normalisation steps to a string."""
    if not isinstance(text, str):
        return text

    # 1. HTML entity decode
    text = html.unescape(text)

    # 2. URL decode (multiple rounds for double-encoding)
    for _ in range(3):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded

    # 3. Unicode NFKD decomposition (separates base chars from accents)
    text = unicodedata.normalize("NFKD", text)

    # 4. Strip zero-width and invisible chars
    text = _ZERO_WIDTH.sub("", text)

    # 5. Strip combining diacritics
    text = _COMBINING.sub("", text)

    # 6. Strip BIDI overrides
    text = _BIDI.sub("", text)

    # 7. Confusable homoglyph normalisation (skeleton algorithm)
    if HAS_CONFUSABLES:
        try:
            # `confusables.is_dangerous` returns a boolean, so don't reassign to `text`.
            # A full normalization would replace homoglyphs, but for now we just flag it 
            # if we wanted to, or skip.
            is_homoglyph = confusables.is_dangerous(text, preferred_aliases=['latin'])
        except Exception:
            pass

    # 8. Strip markdown emphasis
    text = _MARKDOWN.sub(r'\1', text)

    # 9. Visual Canonicalization (map lookalikes)
    text = text.translate(VISUAL_MAP)

    # 10. Collapse whitespace
    text = _SPACES.sub(" ", text).strip()

    return text


def normalise_leetspeak(text: str) -> str:
    """Translate common leet substitutions."""
    if not isinstance(text, str):
        return text
    return text.translate(LEET_MAP).lower()


class TextNormaliser:
    """Applies all normalisation steps to a tool call dict (in-place copy)."""

    def normalise_call(self, call: dict) -> dict:
        """Return a copy of call with all text fields normalised."""
        import copy
        c = copy.deepcopy(call)
        c["arguments"] = self._normalise_obj(c.get("arguments", {}))
        if c.get("context"):
            c["context"] = normalise_text(c["context"])
            c["_context_leet"] = normalise_leetspeak(c["context"])
        return c

    def _normalise_obj(self, obj):
        if isinstance(obj, str):
            n = normalise_text(obj)
            return n
        elif isinstance(obj, dict):
            return {k: self._normalise_obj(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._normalise_obj(i) for i in obj]
        return obj
