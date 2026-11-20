"""
AI Shield - Reversible Privacy Engine.

Sensitive values are replaced with consistent placeholders before text leaves
the gateway, and restored locally after the AI answers:

    "client John Smith, AFM 123456789"  ->  "client [PERSON_001], AFM [AFM_001]"
    AI reply "Dear [PERSON_001], ..."   ->  "Dear John Smith, ..."

The same value always gets the same token inside one Vault, so the model can
still reason about "who is who". A Vault lives only in memory for one request
(backend /api/chat) or one browser session (extension); it is never persisted.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

TOKEN_RE = re.compile(r"\[?\b([A-Z]+(?:_[A-Z]+)*)_(\d{1,6})\b\]?")


class Vault:
    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], str] = {}
        self._by_token: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._by_token)

    def token_for(self, prefix: str, value: str) -> str:
        key = (prefix, " ".join(value.split()))
        token = self._by_key.get(key)
        if token is None:
            self._counters[prefix] = self._counters.get(prefix, 0) + 1
            token = f"[{prefix}_{self._counters[prefix]:03d}]"
            self._by_key[key] = token
            self._by_token[token] = value
        return token

    def value_for(self, token: str) -> str | None:
        return self._by_token.get(token)

    def known_values(self) -> Iterable[tuple[str, str]]:
        """(value, token) pairs, longest value first."""
        return sorted(((v, t) for t, v in self._by_token.items()), key=lambda x: -len(x[0]))


def _word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def pseudonymize(text: str, entities: list[dict[str, Any]], vault: Vault) -> str:
    """Replace scanner entities, plus any value already in the vault, with tokens."""
    spans: list[tuple[int, int, str]] = []
    for e in entities:
        start, end = int(e["start"]), int(e["end"])
        if 0 <= start < end <= len(text):
            spans.append((start, end, vault.token_for(e.get("token_type") or e["type"], text[start:end])))

    # Consistency: a person named earlier in the chat is hidden even when this
    # message mentions them without a label ("make it shorter for John Smith").
    for value, token in vault.known_values():
        if len(value) < 4:
            continue
        pos = text.find(value)
        while pos != -1:
            end = pos + len(value)
            left_ok = pos == 0 or not _word_char(text[pos - 1])
            right_ok = end == len(text) or not _word_char(text[end])
            if left_ok and right_ok:
                spans.append((pos, end, token))
            pos = text.find(value, pos + 1)

    chosen: list[tuple[int, int, str]] = []
    for span in spans:  # scanner spans first, then known values (longest first)
        if not any(span[0] < c[1] and c[0] < span[1] for c in chosen):
            chosen.append(span)
    for start, end, token in sorted(chosen, key=lambda c: -c[0]):
        text = text[:start] + token + text[end:]
    return text


def restore(text: str, vault: Vault) -> str:
    """Put the original values back in place of tokens the vault knows."""
    def repl(m: re.Match) -> str:
        value = vault.value_for(f"[{m.group(1)}_{int(m.group(2)):03d}]")
        return value if value is not None else m.group(0)
    return TOKEN_RE.sub(repl, text)
