"""Behavioral Defense Layer: Raid State Machine, Edit-Bait Forensics, Sender-Chat Spoof & Admin Anomaly Guard."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from dataclasses import dataclass

from protector.config import ChannelGuardConfig, EditBaitConfig, RaidConfig
from protector.models import (
    ChatConfig,
    ChatType,
    EventType,
    MessageSnapshot,
    RaidState,
    RiskSignal,
    TelegramEvent,
    ThreatCategory,
    UserReputation,
)
from protector.normalizer import NormalizedText
from protector.storage import Storage

_RE_TOKENS = re.compile(r"[a-z0-9\u0980-\u09FF]{2,}", re.UNICODE)


def _extract_token_set(text: str) -> set[str]:
    return set(_RE_TOKENS.findall(text.lower()))


def _jaccard_mutation(tokens_a: set[str], tokens_b: set[str]) -> float:
    """Return 0.0 (identical) to 1.0 (completely rewritten)."""
    if not tokens_a and not tokens_b:
        return 0.0
    union = tokens_a | tokens_b
    if not union:
        return 0.0
    return 1.0 - (len(tokens_a & tokens_b) / len(union))


@dataclass
class _ChatRuntimeState:
    raid_state: RaidState = RaidState.NORMAL
    state_changed_at: float = 0.0
    last_threat_at: float = 0.0


class BehavioralAnalyzer:
    """Stateful sliding-window behavioral, raid, edit-bait, and admin-compromise analyzer."""

    def __init__(
        self,
        raid_cfg: RaidConfig,
        edit_cfg: EditBaitConfig,
        channel_cfg: ChannelGuardConfig,
        storage: Storage,
    ) -> None:
        self.raid_cfg = raid_cfg
        self.edit_cfg = edit_cfg
        self.channel_cfg = channel_cfg
        self.storage = storage

        self._chat_states: dict[int, _ChatRuntimeState] = {}
        self._join_windows: dict[int, deque[float]] = defaultdict(deque)
        self._violation_windows: dict[int, deque[float]] = defaultdict(deque)
        self._user_msg_windows: dict[tuple[int, int], deque[tuple[float, str]]] = defaultdict(deque)
        self._admin_post_windows: dict[tuple[int, int], deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------
    # Raid State Machine
    # ------------------------------------------------------------------
    def get_raid_state(self, chat_id: int, now: float) -> RaidState:
        st = self._chat_states.get(chat_id)
        if st is None:
            persisted = self.storage.get_chat_config(chat_id).raid_state
            try:
                initial = RaidState(persisted)
            except ValueError:
                initial = RaidState.NORMAL
            st = _ChatRuntimeState(raid_state=initial, state_changed_at=now, last_threat_at=now)
            self._chat_states[chat_id] = st
            return st.raid_state

        # Automatic cooldown transitions when chat is quiet
        quiet_for = now - st.last_threat_at
        if st.raid_state == RaidState.LOCKDOWN and quiet_for >= self.raid_cfg.lockdown_cooldown_seconds:
            st.raid_state = RaidState.ELEVATED
            st.state_changed_at = now
        elif st.raid_state == RaidState.ELEVATED and quiet_for >= self.raid_cfg.elevated_cooldown_seconds:
            st.raid_state = RaidState.NORMAL
            st.state_changed_at = now

        return st.raid_state

    def set_raid_state(self, chat_id: int, state: RaidState, now: float) -> None:
        st = self._chat_states.setdefault(chat_id, _ChatRuntimeState())
        st.raid_state = state
        st.state_changed_at = now
        st.last_threat_at = now
        cfg = self.storage.get_chat_config(chat_id)
        cfg.raid_state = state.value
        self.storage.upsert_chat_config(cfg)

    def record_join(self, chat_id: int, now: float) -> tuple[RaidState, bool]:
        """Record a member join and return (new_raid_state, triggered_new_lockdown)."""
        prev_state = self.get_raid_state(chat_id, now)
        dq = self._join_windows[chat_id]
        dq.append(now)
        while dq and now - dq[0] > self.raid_cfg.join_window_seconds:
            dq.popleft()

        count = len(dq)
        st = self._chat_states[chat_id]
        triggered_lockdown = False

        if count >= self.raid_cfg.lockdown_joins_threshold:
            if prev_state != RaidState.LOCKDOWN:
                triggered_lockdown = True
            self.set_raid_state(chat_id, RaidState.LOCKDOWN, now)
        elif count >= self.raid_cfg.elevated_joins_threshold and prev_state == RaidState.NORMAL:
            self.set_raid_state(chat_id, RaidState.ELEVATED, now)
        else:
            st.last_threat_at = now if prev_state != RaidState.NORMAL else st.last_threat_at

        return self._chat_states[chat_id].raid_state, triggered_lockdown

    def record_high_risk_violation(self, chat_id: int, now: float) -> tuple[RaidState, bool]:
        """Escalate Raid State if multiple high-risk violations erupt rapidly."""
        prev_state = self.get_raid_state(chat_id, now)
        dq = self._violation_windows[chat_id]
        dq.append(now)
        while dq and now - dq[0] > self.raid_cfg.violation_window_seconds:
            dq.popleft()

        count = len(dq)
        triggered_lockdown = False
        if count >= self.raid_cfg.lockdown_violations_threshold:
            if prev_state != RaidState.LOCKDOWN:
                triggered_lockdown = True
            self.set_raid_state(chat_id, RaidState.LOCKDOWN, now)
        elif count >= self.raid_cfg.elevated_violations_threshold and prev_state == RaidState.NORMAL:
            self.set_raid_state(chat_id, RaidState.ELEVATED, now)

        return self._chat_states[chat_id].raid_state, triggered_lockdown

    # ------------------------------------------------------------------
    # Message, Edit-Bait, Sender-Chat & Admin Analysis
    # ------------------------------------------------------------------
    def analyze(
        self,
        event: TelegramEvent,
        norm: NormalizedText,
        url_count: int,
        untrusted_url_count: int,
        chat_cfg: ChatConfig,
        user_rep: UserReputation | None,
    ) -> tuple[list[RiskSignal], bool, bool]:
        """Return (signals, ban_sender_chat, is_new_member_sandboxed)."""
        signals: list[RiskSignal] = []
        ban_sender_chat = False
        is_sandboxed = False

        # 1. Sender-Chat Channel Spoofing Guard (groups & discussion groups)
        if (
            event.chat_type in {ChatType.GROUP, ChatType.SUPERGROUP}
            and event.sender_chat_id is not None
            and not event.is_anonymous_admin
        ):
            allowed_sender_chats = {event.chat_id}
            if event.linked_chat_id:
                allowed_sender_chats.add(event.linked_chat_id)
            if chat_cfg.linked_parent_channel_id:
                allowed_sender_chats.add(chat_cfg.linked_parent_channel_id)

            if event.sender_chat_id not in allowed_sender_chats:
                ban_sender_chat = True
                signals.append(
                    RiskSignal(
                        layer="behavioral",
                        category=ThreatCategory.IMPERSONATION_SPOOFING,
                        score=76,
                        reason=(
                            f"Unauthorized linked-channel spoofing via sender_chat "
                            f"({event.sender_chat_title or event.sender_chat_id})"
                        ),
                        evidence={"sender_chat_id": event.sender_chat_id},
                    )
                )

        # 2. Delayed Edit-Bait Sabotage Forensics
        if event.event_type in {EventType.EDITED_MESSAGE, EventType.EDITED_CHANNEL_POST}:
            signals.extend(self._analyze_edit_bait(event, norm, url_count))
        elif (
            event.event_type in {EventType.MESSAGE, EventType.CHANNEL_POST}
            and event.message_id is not None
        ):
            self._store_snapshot(event, norm, url_count)

        # 3. Admin Burst / Possible Hijack Anomaly Guard
        if event.is_admin or event.chat_type == ChatType.CHANNEL:
            actor_key = (event.chat_id, event.user_id or event.sender_chat_id or 0)
            dq = self._admin_post_windows[actor_key]
            dq.append(event.timestamp)
            while dq and event.timestamp - dq[0] > self.channel_cfg.admin_burst_window_seconds:
                dq.popleft()
            if len(dq) > self.channel_cfg.admin_burst_max_posts:
                signals.append(
                    RiskSignal(
                        layer="behavioral",
                        category=ThreatCategory.ADMIN_COMPROMISE,
                        score=60,
                        reason=(
                            f"Abnormal admin posting burst ({len(dq)} posts in "
                            f"{self.channel_cfg.admin_burst_window_seconds}s — possible account hijack)"
                        ),
                        evidence={"burst_count": len(dq)},
                    )
                )
            return signals, ban_sender_chat, False

        # 4. Non-Admin Behavioral Signals (Flood, Duplicate Spam, New-Member Sandbox)
        if event.user_id is not None and event.chat_type in {ChatType.GROUP, ChatType.SUPERGROUP}:
            content_hash = hashlib.sha256(norm.folded_ascii.encode("utf-8")).hexdigest()[:16]
            key = (event.chat_id, event.user_id)
            dq = self._user_msg_windows[key]
            dq.append((event.timestamp, content_hash))
            while dq and event.timestamp - dq[0][0] > self.raid_cfg.flood_window_seconds:
                dq.popleft()

            # 4a. Message Flood
            if len(dq) >= self.raid_cfg.flood_max_messages:
                signals.append(
                    RiskSignal(
                        layer="behavioral",
                        category=ThreatCategory.SPAM_SHILL_FLOOD,
                        score=64,
                        reason=f"Message flood detected ({len(dq)} messages in {self.raid_cfg.flood_window_seconds}s)",
                        evidence={"msg_burst": len(dq)},
                    )
                )

            # 4b. Identical Duplicate Spam Burst
            if norm.folded_ascii and len(norm.folded_ascii) >= 12:
                dup_count = sum(1 for _, h in dq if h == content_hash)
                if dup_count >= 3:
                    signals.append(
                        RiskSignal(
                            layer="behavioral",
                            category=ThreatCategory.SPAM_SHILL_FLOOD,
                            score=68,
                            reason=f"Repeated identical spam payload ({dup_count}x in window)",
                            evidence={"duplicate_count": dup_count},
                        )
                    )

            # 4c. New-Member Sandbox Risk Check
            if user_rep is not None:
                membership_age = max(0.0, event.timestamp - user_rep.joined_at)
                is_sandboxed = (
                    membership_age < self.raid_cfg.sandbox_duration_seconds
                    and user_rep.clean_messages < self.raid_cfg.sandbox_clean_messages_required
                )
                if is_sandboxed:
                    # First-second bot spammer posting untrusted link or forward immediately after joining!
                    if membership_age <= 15.0 and (
                        untrusted_url_count > 0 or event.is_forwarded or event.via_bot_id
                    ):
                        signals.append(
                            RiskSignal(
                                layer="behavioral",
                                category=ThreatCategory.RAID_ANOMALY,
                                score=56,
                                reason=f"Instant join-and-spam pattern (untrusted link/forward {membership_age:.1f}s after joining)",
                                evidence={"membership_age_s": round(membership_age, 1)},
                            )
                        )
                    elif untrusted_url_count > 0 or event.is_forwarded:
                        signals.append(
                            RiskSignal(
                                layer="behavioral",
                                category=ThreatCategory.SPAM_SHILL_FLOOD,
                                score=24,
                                reason="Sandboxed new member posting untrusted external link or forwarded message",
                                evidence={"clean_messages": user_rep.clean_messages},
                            )
                        )

        return signals, ban_sender_chat, is_sandboxed

    def _store_snapshot(self, event: TelegramEvent, norm: NormalizedText, url_count: int) -> None:
        assert event.message_id is not None
        tokens = sorted(_extract_token_set(norm.folded_ascii))[:40]
        snap = MessageSnapshot(
            chat_id=event.chat_id,
            message_id=event.message_id,
            user_id=event.user_id,
            content_sha256=hashlib.sha256(norm.folded_ascii.encode("utf-8")).hexdigest(),
            token_fingerprint=" ".join(tokens),
            text_length=len(norm.cleaned),
            url_count=url_count,
            has_media=event.media is not None,
            created_at=event.original_date or event.timestamp,
        )
        self.storage.save_message_snapshot(snap)

    def _analyze_edit_bait(
        self, event: TelegramEvent, norm: NormalizedText, new_url_count: int
    ) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        if event.message_id is None:
            return signals

        snap = self.storage.get_message_snapshot(event.chat_id, event.message_id)
        if snap is None:
            return signals

        edit_ts = event.edit_date or event.timestamp
        delay_sec = max(0.0, edit_ts - snap.created_at)
        is_delayed = delay_sec >= self.edit_cfg.delayed_edit_seconds

        # 1. URL Injection in Edited Message (original had 0 URLs -> edit introduces URL!)
        if snap.url_count == 0 and new_url_count > 0:
            score = self.edit_cfg.url_injection_risk if is_delayed else 25
            signals.append(
                RiskSignal(
                    layer="edit_bait",
                    category=ThreatCategory.EDIT_BAIT_SABOTAGE,
                    score=score,
                    reason=(
                        f"Edit-Bait URL injection detected "
                        f"(0 -> {new_url_count} URLs after {int(delay_sec)}s delay)"
                    ),
                    evidence={"delay_sec": int(delay_sec), "new_urls": new_url_count},
                )
            )

        # 2. High-Mutation Delayed Rewrite (completely replacing an old benign message)
        old_tokens = set(snap.token_fingerprint.split()) if snap.token_fingerprint else set()
        new_tokens = _extract_token_set(norm.folded_ascii)
        mutation = _jaccard_mutation(old_tokens, new_tokens)

        if is_delayed and mutation >= self.edit_cfg.high_mutation_ratio and len(new_tokens) >= 3:
            signals.append(
                RiskSignal(
                    layer="edit_bait",
                    category=ThreatCategory.EDIT_BAIT_SABOTAGE,
                    score=self.edit_cfg.high_mutation_risk,
                    reason=(
                        f"Delayed high-mutation edit detected "
                        f"({mutation:.0%} rewrite after {int(delay_sec)}s — possible takedown sabotage)"
                    ),
                    evidence={"delay_sec": int(delay_sec), "mutation_ratio": round(mutation, 2)},
                )
            )

        return signals
