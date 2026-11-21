"""Reputation, Local Federation Sync, Behavioral Trust Ledger & Optional Async CAS Lookup."""

from __future__ import annotations

import asyncio
import json
import urllib.request

from protector.config import ReputationConfig
from protector.models import (
    ChatConfig,
    RiskSignal,
    TelegramEvent,
    ThreatCategory,
    UserReputation,
)
from protector.storage import Storage

# Telegram user IDs above ~7.5B generally indicate very recently created accounts (2025-2026+)
FRESH_ACCOUNT_ID_THRESHOLD = 7_500_000_000


class ReputationAnalyzer:
    """Checks local Federation bans, CAS (Combot Anti-Spam), and user behavioral trust."""

    def __init__(self, config: ReputationConfig, storage: Storage) -> None:
        self.config = config
        self.storage = storage

    async def analyze(
        self, event: TelegramEvent, chat_cfg: ChatConfig
    ) -> tuple[list[RiskSignal], UserReputation | None]:
        signals: list[RiskSignal] = []

        # 1. Check Spoofed Sender Chat against Federation Ban List
        if event.sender_chat_id is not None and self.config.federation_sync_enabled:
            fed_chat = self.storage.get_federation_ban(
                event.sender_chat_id, federation_id=chat_cfg.federation_id
            )
            if fed_chat:
                signals.append(
                    RiskSignal(
                        layer="reputation",
                        category=ThreatCategory.REPUTATION_FEDBAN,
                        score=95,
                        reason=f"Sender channel is Federation-Banned: {fed_chat['reason']}",
                        hard_block=True,
                        evidence={"federation_id": chat_cfg.federation_id},
                    )
                )

        if event.user_id is None:
            return signals, None

        # 2. Check User against Local Federation Ban List
        if self.config.federation_sync_enabled and not event.is_admin:
            fed = self.storage.get_federation_ban(
                event.user_id, federation_id=chat_cfg.federation_id
            )
            if fed:
                signals.append(
                    RiskSignal(
                        layer="reputation",
                        category=ThreatCategory.REPUTATION_FEDBAN,
                        score=96,
                        reason=f"User is Federation-Banned across network: {fed['reason']}",
                        hard_block=True,
                        evidence={
                            "federation_id": chat_cfg.federation_id,
                            "source_chat_id": fed.get("source_chat_id"),
                        },
                    )
                )

        # 3. Load / Initialize Behavioral Trust Record
        rep = self.storage.get_user_reputation(
            chat_id=event.chat_id,
            user_id=event.user_id,
            default_trust=self.config.initial_trust_score,
            now=event.timestamp,
        )

        # Repeat offender strike penalty
        if not event.is_admin and rep.strikes >= 2:
            signals.append(
                RiskSignal(
                    layer="reputation",
                    category=ThreatCategory.REPUTATION_FEDBAN,
                    score=min(40, rep.strikes * 14),
                    reason=f"Repeat offender history ({rep.strikes} prior strikes, trust={rep.trust_score}/100)",
                    evidence={"strikes": rep.strikes, "trust_score": rep.trust_score},
                )
            )

        # Fresh burner account heuristic (no username + very high ID + zero clean history)
        if (
            not event.is_admin
            and event.user_id >= FRESH_ACCOUNT_ID_THRESHOLD
            and not event.username
            and rep.clean_messages == 0
        ):
            signals.append(
                RiskSignal(
                    layer="reputation",
                    category=ThreatCategory.RAID_ANOMALY,
                    score=12,
                    reason="Fresh high-ID account without username and zero clean history",
                    evidence={"user_id": event.user_id},
                )
            )

        # 4. Optional Non-Blocking CAS (Combot Anti-Spam) Lookup with Local TTL Cache
        if self.config.cas_enabled and not event.is_admin:
            is_cas_banned = await self._check_cas(event.user_id)
            if is_cas_banned:
                signals.append(
                    RiskSignal(
                        layer="reputation",
                        category=ThreatCategory.REPUTATION_FEDBAN,
                        score=92,
                        reason="User listed in global CAS (Combot Anti-Spam) threat database",
                        hard_block=True,
                        evidence={"source": "CAS"},
                    )
                )

        return signals, rep

    async def _check_cas(self, user_id: int) -> bool:
        cached = self.storage.get_cas_cache(user_id, self.config.cas_cache_ttl_seconds)
        if cached is not None:
            return cached

        def _fetch() -> tuple[bool, int]:
            url = f"https://api.cas.chat/check?user_id={user_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "AegisTG-Protector/1.0"})
            with urllib.request.urlopen(req, timeout=self.config.cas_timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                is_banned = bool(data.get("ok"))
                offenses = int((data.get("result") or {}).get("offenses", 0))
                return is_banned, offenses

        try:
            is_banned, offenses = await asyncio.to_thread(_fetch)
            self.storage.set_cas_cache(user_id, is_banned, offenses)
            return is_banned
        except Exception:
            # Fail-open safely so external API outages never disrupt protection
            return False

    def record_clean_interaction(self, rep: UserReputation) -> None:
        rep.clean_messages += 1
        if rep.trust_score < 100:
            rep.trust_score = min(100, rep.trust_score + 2)
        self.storage.save_user_reputation(rep)

    def record_violation(self, rep: UserReputation, severity_score: int, now: float) -> None:
        rep.strikes += 1
        penalty = 20 if severity_score < 75 else 40
        rep.trust_score = max(0, rep.trust_score - penalty)
        rep.last_violation_at = now
        self.storage.save_user_reputation(rep)
