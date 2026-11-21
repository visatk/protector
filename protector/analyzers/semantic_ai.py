"""Pluggable Gray-Zone Semantic AI Judge (Strict Zero-Training / PII-Redacted Compliance).

Invoked ONLY for ambiguous gray-zone scores (default 35..74) so 95%+ of traffic
is handled deterministically in <15ms with zero API cost and zero data exposure.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Any

from protector.config import SemanticAIConfig
from protector.models import RiskSignal, TelegramEvent, ThreatCategory
from protector.normalizer import redact_pii

SYSTEM_PROMPT = """You are a strict Telegram Trust & Safety compliance classifier.
Evaluate the SINGLE isolated message excerpt for violations of Telegram Terms of Service:
1. CSAM_EXPLOITATION (child exploitation)
2. VIOLENCE_TERRORISM (terrorism, incitement to violence, gore)
3. ILLEGAL_GOODS_CYBERCRIME (drugs, weapons, carding, forged documents)
4. SCAM_PHISHING_SAFEGUARD (phishing, fake Telegram support/Safeguard, crypto drainers, MFS/bKash/Nagad OTP scams)
5. DOXING_PII_LEAK (doxing, private info leaks)
6. COPYRIGHT_DMCA_RISK (pirated media/courses/cracks distribution)
7. MALWARE_EXPLOIT (malware, stealer, malicious APK)
8. SPAM_SHILL_FLOOD (unsolicited scammy promotion)

Distinguish legitimate educational/news/security discussions ABOUT threats from actual malicious intent.
Respond ONLY with compact JSON:
{"violates": true|false, "category": "<ONE_OF_ABOVE_OR_NONE>", "score": 0-100, "reason": "<short reason>"}"""


class SemanticAIJudge:
    """Zero-retention, PII-redacted optional LLM classifier for gray-zone ambiguity."""

    def __init__(self, config: SemanticAIConfig) -> None:
        self.config = config

    @property
    def is_enabled(self) -> bool:
        return bool(self.config.enabled and self.config.api_key)

    async def evaluate(
        self, event: TelegramEvent, text: str, deterministic_score: int
    ) -> RiskSignal | None:
        if not self.is_enabled or not text.strip():
            return None

        # Strictly redact PII before any outbound network call (Telegram Privacy Compliance)
        safe_excerpt = redact_pii(text, max_len=600)
        user_payload = (
            f"ChatType: {event.chat_type.value}\n"
            f"EventType: {event.event_type.value}\n"
            f"PreliminaryRisk: {deterministic_score}\n"
            f"MessageExcerpt: {safe_excerpt}"
        )

        try:
            verdict = await asyncio.to_thread(self._call_provider, user_payload)
        except Exception:
            # Fail safely back to deterministic layers on timeout/network failure
            return None

        if not verdict or not verdict.get("violates"):
            return None

        raw_cat = str(verdict.get("category", "SPAM_SHILL_FLOOD")).upper()
        try:
            category = ThreatCategory(raw_cat)
        except ValueError:
            category = ThreatCategory.SCAM_PHISHING_SAFEGUARD

        ai_score = max(0, min(100, int(verdict.get("score", 60))))
        reason = str(verdict.get("reason", "Semantic AI flagged policy violation"))[:160]

        return RiskSignal(
            layer="semantic_ai",
            category=category,
            score=ai_score,
            reason=f"Semantic AI Judge: {reason}",
            hard_block=category in {ThreatCategory.CSAM_EXPLOITATION, ThreatCategory.VIOLENCE_TERRORISM}
            and ai_score >= 90,
            evidence={"provider": self.config.provider, "model": self.config.model},
        )

    def _call_provider(self, user_payload: str) -> dict[str, Any] | None:
        if self.config.provider == "gemini":
            return self._call_gemini(user_payload)
        return self._call_openai_compatible(user_payload)

    def _call_openai_compatible(self, user_payload: str) -> dict[str, Any] | None:
        url = f"{self.config.api_base_url}/chat/completions"
        body = json.dumps(
            {
                "model": self.config.model,
                "temperature": 0.0,
                "max_tokens": 140,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_payload},
                ],
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        return json.loads(content)

    def _call_gemini(self, user_payload: str) -> dict[str, Any] | None:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.config.model}:generateContent?key={self.config.api_key}"
        )
        body = json.dumps(
            {
                "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": [{"parts": [{"text": user_payload}]}],
                "generationConfig": {
                    "temperature": 0.0,
                    "responseMimeType": "application/json",
                },
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content = data["candidates"][0]["content"]["parts"][0]["text"]
        return json.loads(content)
