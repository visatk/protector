"""Core domain models for AegisTG Telegram Protector."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    MESSAGE = "message"
    EDITED_MESSAGE = "edited_message"
    CHANNEL_POST = "channel_post"
    EDITED_CHANNEL_POST = "edited_channel_post"
    CHAT_MEMBER = "chat_member"
    MY_CHAT_MEMBER = "my_chat_member"
    CHAT_JOIN_REQUEST = "chat_join_request"
    DRAFT_CHECK = "draft_check"


class ChatType(str, Enum):
    PRIVATE = "private"
    GROUP = "group"
    SUPERGROUP = "supergroup"
    CHANNEL = "channel"


class RaidState(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    LOCKDOWN = "LOCKDOWN"


class ThreatCategory(str, Enum):
    CSAM_EXPLOITATION = "CSAM_EXPLOITATION"
    VIOLENCE_TERRORISM = "VIOLENCE_TERRORISM"
    ILLEGAL_GOODS_CYBERCRIME = "ILLEGAL_GOODS_CYBERCRIME"
    SCAM_PHISHING_SAFEGUARD = "SCAM_PHISHING_SAFEGUARD"
    DOXING_PII_LEAK = "DOXING_PII_LEAK"
    COPYRIGHT_DMCA_RISK = "COPYRIGHT_DMCA_RISK"
    MALWARE_EXPLOIT = "MALWARE_EXPLOIT"
    SPAM_SHILL_FLOOD = "SPAM_SHILL_FLOOD"
    RAID_ANOMALY = "RAID_ANOMALY"
    EDIT_BAIT_SABOTAGE = "EDIT_BAIT_SABOTAGE"
    IMPERSONATION_SPOOFING = "IMPERSONATION_SPOOFING"
    ADMIN_COMPROMISE = "ADMIN_COMPROMISE"
    REPUTATION_FEDBAN = "REPUTATION_FEDBAN"
    OBFUSCATION_EVASION = "OBFUSCATION_EVASION"


class VerdictAction(str, Enum):
    ALLOW = "ALLOW"
    WARN_MONITOR = "WARN_MONITOR"
    DELETE_ONLY = "DELETE_ONLY"
    DELETE_RESTRICT = "DELETE_RESTRICT"
    DELETE_BAN = "DELETE_BAN"
    HARD_BLOCK_FEDBAN = "HARD_BLOCK_FEDBAN"
    QUARANTINE_CHANNEL_POST = "QUARANTINE_CHANNEL_POST"
    ALERT_OWNER_ONLY = "ALERT_OWNER_ONLY"


@dataclass(slots=True)
class EntityInfo:
    """Normalized representation of a Telegram MessageEntity."""

    type: str
    offset: int = 0
    length: int = 0
    url: str | None = None
    user_id: int | None = None


@dataclass(slots=True)
class MediaInfo:
    """Normalized metadata and optional raw bytes for uploaded files/media."""

    media_type: str  # photo, document, video, animation, sticker, audio, voice
    file_id: str | None = None
    file_unique_id: str | None = None
    file_name: str | None = None
    mime_type: str | None = None
    file_size: int | None = None
    raw_bytes: bytes | None = None  # Populated optionally for magic-byte / dHash analysis


@dataclass(slots=True)
class TelegramEvent:
    """Unified, transport-agnostic representation of an incoming Telegram event."""

    event_type: EventType
    chat_id: int
    chat_type: ChatType
    timestamp: float
    message_id: int | None = None
    user_id: int | None = None
    username: str | None = None
    full_name: str | None = None
    is_bot: bool = False
    is_admin: bool = False
    is_anonymous_admin: bool = False
    sender_chat_id: int | None = None
    sender_chat_title: str | None = None
    linked_chat_id: int | None = None
    is_direct_messages: bool = False
    is_forwarded: bool = False
    forward_from_chat_id: int | None = None
    via_bot_id: int | None = None
    text: str = ""
    entities: list[EntityInfo] = field(default_factory=list)
    media: MediaInfo | None = None
    edit_date: float | None = None
    original_date: float | None = None
    raw_update: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RiskSignal:
    """Single explainable threat signal emitted by an analyzer layer."""

    layer: str
    category: ThreatCategory
    score: int  # 0..100 contribution
    reason: str
    hard_block: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvaluationResult:
    """Final aggregated decision produced by the 9-Layer Protection Engine."""

    risk_score: int  # 0..100
    action: VerdictAction
    signals: list[RiskSignal] = field(default_factory=list)
    raid_state: RaidState = RaidState.NORMAL
    trigger_lockdown: bool = False
    ban_sender_chat: bool = False
    revoke_messages: bool = False
    restrict_seconds: int = 0
    alert_owner: bool = False
    federation_ban: bool = False
    used_semantic_ai: bool = False
    latency_ms: float = 0.0
    summary: str = ""
    incident_id: str | None = None

    @property
    def primary_category(self) -> ThreatCategory | None:
        if not self.signals:
            return None
        top = max(self.signals, key=lambda s: (1 if s.hard_block else 0, s.score))
        return top.category


@dataclass(slots=True)
class ChatConfig:
    """Per-chat protection settings persisted in storage."""

    chat_id: int
    chat_type: str = "supergroup"
    title: str = ""
    enabled: bool = True
    alert_chat_id: int | None = None
    linked_parent_channel_id: int | None = None
    strict_channel_guard: bool = False
    require_join_verification: bool = False
    allowlist_domains: list[str] = field(default_factory=list)
    raid_state: str = RaidState.NORMAL.value
    saved_permissions_json: str | None = None
    federation_id: str = "default"


@dataclass(slots=True)
class UserReputation:
    """Behavioral trust record for a user within a chat."""

    chat_id: int
    user_id: int
    trust_score: int = 50
    joined_at: float = 0.0
    clean_messages: int = 0
    strikes: int = 0
    last_violation_at: float | None = None


@dataclass(slots=True)
class MessageSnapshot:
    """Privacy-safe structural fingerprint used to detect Delayed Edit-Bait sabotage."""

    chat_id: int
    message_id: int
    user_id: int | None
    content_sha256: str
    token_fingerprint: str  # Sorted unique normalized tokens (hashed or compact)
    text_length: int
    url_count: int
    has_media: bool
    created_at: float


@dataclass(slots=True)
class IncidentRecord:
    """Privacy-redacted forensic record for admin alerts and abuse@telegram.org appeals."""

    incident_id: str
    timestamp: float
    chat_id: int
    chat_type: str
    event_type: str
    actor_id: int | None
    sender_chat_id: int | None
    message_id: int | None
    primary_category: str
    risk_score: int
    action_taken: str
    signals_summary: list[str]
    latency_ms: float
    redacted_preview: str = ""


@dataclass(slots=True)
class AuditFinding:
    """Single security posture check produced by /audit."""

    check_id: str
    title: str
    severity: str  # PASS, INFO, WARNING, CRITICAL
    points_earned: int
    points_possible: int
    recommendation: str


@dataclass(slots=True)
class AuditReport:
    """Comprehensive security posture score for a Telegram group or channel."""

    chat_id: int
    chat_type: str
    title: str
    score: int  # 0..100
    grade: str  # A+, A, B, C, D, F
    findings: list[AuditFinding] = field(default_factory=list)
    opsec_checklist: list[str] = field(default_factory=list)
