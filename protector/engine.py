"""Core 9-Layer Risk Aggregation & Decision Orchestrator for AegisTG Protector v2.0."""

from __future__ import annotations

import time
import uuid

from protector.analyzers.behavioral import BehavioralAnalyzer
from protector.analyzers.media_guard import MediaGuardAnalyzer
from protector.analyzers.reputation import ReputationAnalyzer
from protector.analyzers.semantic_ai import SemanticAIJudge
from protector.analyzers.text_policy import TextPolicyAnalyzer
from protector.analyzers.url_intel import UrlIntelAnalyzer
from protector.config import BotConfig
from protector.models import (
    ChatConfig,
    ChatType,
    EvaluationResult,
    EventType,
    IncidentRecord,
    RaidState,
    RiskSignal,
    TelegramEvent,
    ThreatCategory,
    VerdictAction,
)
from protector.normalizer import normalize_text, redact_pii
from protector.security import RuntimeMetrics, clamp_text_for_inspection
from protector.storage import Storage

# Zero-tolerance categories can NEVER be muted by per-chat soft exceptions
NON_MUTABLE_CATEGORIES = frozenset(
    {
        ThreatCategory.CSAM_EXPLOITATION,
        ThreatCategory.VIOLENCE_TERRORISM,
        ThreatCategory.MALWARE_EXPLOIT,
    }
)


class ProtectionEngine:
    """Orchestrates all 9 defense layers into a deterministic, auditable Verdict."""

    def __init__(
        self,
        config: BotConfig,
        storage: Storage,
        metrics: RuntimeMetrics | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.metrics = metrics or RuntimeMetrics()

        self.text_analyzer = TextPolicyAnalyzer()
        self.url_analyzer = UrlIntelAnalyzer(config.urls)
        self.media_analyzer = MediaGuardAnalyzer(config.media, storage)
        self.behavioral = BehavioralAnalyzer(
            config.raid, config.edit_bait, config.channel_guard, storage
        )
        self.reputation = ReputationAnalyzer(config.reputation, storage)
        self.semantic_ai = SemanticAIJudge(config.semantic_ai)

    async def evaluate(self, event: TelegramEvent) -> EvaluationResult:
        t0 = time.perf_counter()
        is_dry_run = event.event_type == EventType.DRAFT_CHECK
        chat_cfg = self.storage.get_chat_config(event.chat_id)

        if not chat_cfg.enabled and not is_dry_run:
            return EvaluationResult(
                risk_score=0,
                action=VerdictAction.ALLOW,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                summary="Protection disabled for this chat",
            )

        raid_state = self.behavioral.get_raid_state(event.chat_id, event.timestamp)
        all_signals: list[RiskSignal] = []

        # Layer 1 & 2: ReDoS-safe clamp & deep Unicode normalization
        clamped_text = clamp_text_for_inspection(event.text)
        norm = normalize_text(clamped_text)

        # Layer 3: Reputation, Local Federation Bans & CAS
        user_rep = None
        if not is_dry_run:
            rep_signals, user_rep = await self.reputation.analyze(event, chat_cfg)
            all_signals.extend(rep_signals)

        # Layer 4: 8-Category Multilingual Text Policy + Obfuscation Evasion
        all_signals.extend(self.text_analyzer.analyze(event, norm))

        # Layer 5: PSL + IDNA URL & Entity Intelligence
        url_signals, url_count, untrusted_url_count = self.url_analyzer.analyze(event, norm, chat_cfg)
        all_signals.extend(url_signals)

        # Layer 6: Media, Malware Extension, Decompression Bomb & BK-Tree dHash Guard
        all_signals.extend(self.media_analyzer.analyze(event))

        # Layer 7: Behavioral, Sender-Chat Spoofing, Edit-Bait & Admin Anomaly Guard
        ban_sender_chat = False
        is_sandboxed = False
        if not is_dry_run:
            beh_signals, ban_sender_chat, is_sandboxed = self.behavioral.analyze(
                event, norm, url_count, untrusted_url_count, chat_cfg, user_rep
            )
            all_signals.extend(beh_signals)

        # Filter per-chat soft-exception muted rules (never muting zero-tolerance categories!)
        if not is_dry_run and all_signals:
            muted_rules = self.storage.get_muted_rules(event.chat_id)
            if muted_rules:
                all_signals = [
                    s
                    for s in all_signals
                    if s.hard_block
                    or s.category in NON_MUTABLE_CATEGORIES
                    or str(s.evidence.get("rule_id", "")) not in muted_rules
                ]

        det_score, has_hard_block = self._aggregate_score(
            all_signals,
            raid_state=raid_state,
            is_sandboxed=is_sandboxed,
            user_trust=user_rep.trust_score if user_rep else 50,
            clean_messages=user_rep.clean_messages if user_rep else 0,
            is_admin=event.is_admin,
        )

        # Layer 8: Optional Pluggable Gray-Zone Semantic AI Judge (Strictly 35..74)
        used_ai = False
        if (
            not has_hard_block
            and self.semantic_ai.is_enabled
            and self.config.thresholds.semantic_ai_min
            <= det_score
            <= self.config.thresholds.semantic_ai_max
        ):
            ai_sig = await self.semantic_ai.evaluate(event, norm.cleaned, det_score)
            if ai_sig is not None:
                used_ai = True
                all_signals.append(ai_sig)
                det_score, has_hard_block = self._aggregate_score(
                    all_signals,
                    raid_state=raid_state,
                    is_sandboxed=is_sandboxed,
                    user_trust=user_rep.trust_score if user_rep else 50,
                    clean_messages=user_rep.clean_messages if user_rep else 0,
                    is_admin=event.is_admin,
                )

        # Layer 9: Map final risk score + chat type into a concrete ActionPlan
        result = self._build_decision(
            event=event,
            chat_cfg=chat_cfg,
            signals=all_signals,
            risk_score=det_score,
            has_hard_block=has_hard_block,
            raid_state=raid_state,
            ban_sender_chat=ban_sender_chat,
            used_ai=used_ai,
            strikes=user_rep.strikes if user_rep else 0,
        )

        if not is_dry_run:
            if result.action == VerdictAction.ALLOW:
                if user_rep is not None and not event.is_admin:
                    self.reputation.record_clean_interaction(user_rep)
                result.latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                self.metrics.record_evaluation(blocked=False, latency_ms=result.latency_ms)
                return result

            if user_rep is not None and not event.is_admin:
                self.reputation.record_violation(user_rep, result.risk_score, event.timestamp)

            if (
                event.chat_type in {ChatType.GROUP, ChatType.SUPERGROUP}
                and result.risk_score >= self.config.thresholds.delete_ban
            ):
                new_raid_state, triggered_lockdown = self.behavioral.record_high_risk_violation(
                    event.chat_id, event.timestamp
                )
                result.raid_state = new_raid_state
                result.trigger_lockdown = triggered_lockdown
                if triggered_lockdown:
                    self.metrics.lockdowns_triggered += 1

            if result.federation_ban and self.config.reputation.federation_sync_enabled:
                entity_id = event.sender_chat_id if result.ban_sender_chat else event.user_id
                if entity_id is not None:
                    self.storage.add_federation_ban(
                        entity_id=entity_id,
                        reason=result.summary[:180],
                        category=(
                            result.primary_category.value
                            if result.primary_category
                            else "UNKNOWN"
                        ),
                        source_chat_id=event.chat_id,
                        federation_id=chat_cfg.federation_id,
                        entity_type="channel" if result.ban_sender_chat else "user",
                    )

            result.latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            result.incident_id = self._persist_incident(event, result, norm.cleaned)
            self.metrics.record_evaluation(blocked=True, latency_ms=result.latency_ms)
            return result

        result.latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return result

    def _aggregate_score(
        self,
        signals: list[RiskSignal],
        raid_state: RaidState,
        is_sandboxed: bool,
        user_trust: int,
        clean_messages: int,
        is_admin: bool,
    ) -> tuple[int, bool]:
        if not signals:
            return 0, False

        hard_blocks = [s for s in signals if s.hard_block]
        if hard_blocks:
            top_hb = max(s.score for s in hard_blocks)
            return min(100, max(92, top_hb)), True

        ordered = sorted((s.score for s in signals), reverse=True)
        combined = float(ordered[0])
        if len(ordered) >= 2:
            combined += 0.35 * ordered[1]
        for extra in ordered[2:]:
            combined += 0.18 * extra

        if not is_admin:
            if is_sandboxed:
                combined *= 1.18
            if raid_state == RaidState.ELEVATED:
                combined *= 1.20
            elif raid_state == RaidState.LOCKDOWN:
                combined *= 1.35
            elif user_trust >= 80 and clean_messages >= 10:
                combined *= 0.85

        return max(0, min(100, int(round(combined)))), False

    def _build_decision(
        self,
        event: TelegramEvent,
        chat_cfg: ChatConfig,
        signals: list[RiskSignal],
        risk_score: int,
        has_hard_block: bool,
        raid_state: RaidState,
        ban_sender_chat: bool,
        used_ai: bool,
        strikes: int,
    ) -> EvaluationResult:
        th = self.config.thresholds
        summary = (
            "; ".join(dict.fromkeys(s.reason for s in sorted(signals, key=lambda x: -x.score)[:3]))
            if signals
            else "Clean — no Telegram ToS threats detected"
        )

        if event.event_type == EventType.DRAFT_CHECK:
            if has_hard_block or risk_score >= th.delete_ban:
                action = VerdictAction.QUARANTINE_CHANNEL_POST
            elif risk_score >= th.warn:
                action = VerdictAction.WARN_MONITOR
            else:
                action = VerdictAction.ALLOW
            return EvaluationResult(
                risk_score=risk_score,
                action=action,
                signals=signals,
                raid_state=raid_state,
                used_semantic_ai=used_ai,
                summary=summary,
            )

        if event.chat_type == ChatType.CHANNEL or event.event_type in {
            EventType.CHANNEL_POST,
            EventType.EDITED_CHANNEL_POST,
        }:
            strict = chat_cfg.strict_channel_guard or self.config.channel_guard.strict_auto_quarantine
            quarantine_floor = self.config.channel_guard.auto_quarantine_min_score
            if (has_hard_block or risk_score >= quarantine_floor) and strict:
                return EvaluationResult(
                    risk_score=risk_score,
                    action=VerdictAction.QUARANTINE_CHANNEL_POST,
                    signals=signals,
                    raid_state=raid_state,
                    alert_owner=True,
                    used_semantic_ai=used_ai,
                    summary=summary,
                )
            if risk_score >= th.warn:
                return EvaluationResult(
                    risk_score=risk_score,
                    action=VerdictAction.ALERT_OWNER_ONLY,
                    signals=signals,
                    raid_state=raid_state,
                    alert_owner=True,
                    used_semantic_ai=used_ai,
                    summary=summary,
                )
            return EvaluationResult(
                risk_score=risk_score,
                action=VerdictAction.ALLOW,
                signals=signals,
                raid_state=raid_state,
                used_semantic_ai=used_ai,
                summary=summary,
            )

        if event.is_admin:
            if has_hard_block or risk_score >= 85:
                return EvaluationResult(
                    risk_score=risk_score,
                    action=VerdictAction.ALERT_OWNER_ONLY,
                    signals=signals,
                    raid_state=raid_state,
                    alert_owner=True,
                    used_semantic_ai=used_ai,
                    summary=f"[ADMIN ALERT] {summary}",
                )
            return EvaluationResult(
                risk_score=risk_score,
                action=VerdictAction.ALLOW,
                signals=signals,
                raid_state=raid_state,
                used_semantic_ai=used_ai,
                summary=summary,
            )

        if has_hard_block or risk_score >= th.hard_block_fedban:
            return EvaluationResult(
                risk_score=risk_score,
                action=VerdictAction.HARD_BLOCK_FEDBAN,
                signals=signals,
                raid_state=raid_state,
                ban_sender_chat=ban_sender_chat,
                revoke_messages=True,
                alert_owner=True,
                federation_ban=True,
                used_semantic_ai=used_ai,
                summary=summary,
            )

        if risk_score >= th.delete_ban or (risk_score >= th.delete_restrict and strikes >= 2):
            return EvaluationResult(
                risk_score=risk_score,
                action=VerdictAction.DELETE_BAN,
                signals=signals,
                raid_state=raid_state,
                ban_sender_chat=ban_sender_chat,
                revoke_messages=True,
                alert_owner=risk_score >= 82,
                federation_ban=ban_sender_chat,
                used_semantic_ai=used_ai,
                summary=summary,
            )

        if risk_score >= th.delete_restrict:
            mute_hours = 1 if strikes == 0 else (12 if strikes == 1 else 24)
            return EvaluationResult(
                risk_score=risk_score,
                action=VerdictAction.DELETE_RESTRICT,
                signals=signals,
                raid_state=raid_state,
                ban_sender_chat=ban_sender_chat,
                restrict_seconds=mute_hours * 3600,
                used_semantic_ai=used_ai,
                summary=summary,
            )

        if risk_score >= th.warn:
            action = (
                VerdictAction.DELETE_ONLY
                if raid_state in {RaidState.ELEVATED, RaidState.LOCKDOWN}
                else VerdictAction.WARN_MONITOR
            )
            return EvaluationResult(
                risk_score=risk_score,
                action=action,
                signals=signals,
                raid_state=raid_state,
                used_semantic_ai=used_ai,
                summary=summary,
            )

        return EvaluationResult(
            risk_score=risk_score,
            action=VerdictAction.ALLOW,
            signals=signals,
            raid_state=raid_state,
            used_semantic_ai=used_ai,
            summary=summary,
        )

    def _persist_incident(
        self, event: TelegramEvent, result: EvaluationResult, cleaned_text: str
    ) -> str:
        incident_id = uuid.uuid4().hex[:10]
        inc = IncidentRecord(
            incident_id=incident_id,
            timestamp=event.timestamp,
            chat_id=event.chat_id,
            chat_type=event.chat_type.value,
            event_type=event.event_type.value,
            actor_id=event.user_id,
            sender_chat_id=event.sender_chat_id,
            message_id=event.message_id,
            primary_category=(
                result.primary_category.value if result.primary_category else "POLICY_RISK"
            ),
            risk_score=result.risk_score,
            action_taken=result.action.value,
            signals_summary=[f"[{s.layer}:{s.score}] {s.reason}" for s in result.signals],
            latency_ms=result.latency_ms,
            redacted_preview=redact_pii(cleaned_text, max_len=140),
        )
        self.storage.record_incident(inc)
        return incident_id
