"""Configuration management for AegisTG Protector."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ThresholdsConfig:
    warn: int = 35
    delete_restrict: int = 55
    delete_ban: int = 75
    hard_block_fedban: int = 90
    semantic_ai_min: int = 35
    semantic_ai_max: int = 74


@dataclass
class RaidConfig:
    join_window_seconds: int = 60
    elevated_joins_threshold: int = 8
    lockdown_joins_threshold: int = 20
    violation_window_seconds: int = 30
    elevated_violations_threshold: int = 3
    lockdown_violations_threshold: int = 8
    elevated_cooldown_seconds: int = 600
    lockdown_cooldown_seconds: int = 300
    sandbox_duration_seconds: int = 600
    sandbox_clean_messages_required: int = 3
    flood_window_seconds: int = 10
    flood_max_messages: int = 6


@dataclass
class EditBaitConfig:
    delayed_edit_seconds: int = 60
    url_injection_risk: int = 45
    high_mutation_ratio: float = 0.65
    high_mutation_risk: int = 30
    snapshot_ttl_days: int = 7


@dataclass
class ChannelGuardConfig:
    strict_auto_quarantine: bool = False
    auto_quarantine_min_score: int = 80
    admin_burst_window_seconds: int = 60
    admin_burst_max_posts: int = 10


@dataclass
class ReputationConfig:
    cas_enabled: bool = False
    cas_timeout_seconds: float = 1.5
    cas_cache_ttl_seconds: int = 21600
    initial_trust_score: int = 50
    federation_sync_enabled: bool = True


@dataclass
class MediaConfig:
    dhash_hamming_threshold: int = 8
    viral_media_window_seconds: int = 300
    viral_media_unique_users: int = 3
    dangerous_extensions: list[str] = field(
        default_factory=lambda: [
            ".apk", ".xapk", ".exe", ".msi", ".scr", ".bat", ".cmd",
            ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".lnk",
            ".pif", ".com", ".jar", ".sh", ".dmg", ".pkg", ".iso", ".reg",
        ]
    )


@dataclass
class UrlsConfig:
    allowlist_domains: list[str] = field(
        default_factory=lambda: [
            "telegram.org", "core.telegram.org", "t.me", "github.com",
            "wikipedia.org", "youtube.com", "youtu.be", "google.com",
        ]
    )
    denylist_domains: list[str] = field(
        default_factory=lambda: [
            "telegram-verify.com", "t-safeguard.com", "safeguard-verify.xyz",
            "telegram-antispam.org", "web-telegram-login.com",
        ]
    )
    shortener_domains: list[str] = field(
        default_factory=lambda: [
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy",
            "cutt.ly", "shorturl.at", "rebrand.ly", "ow.ly", "clck.ru", "tiny.cc",
        ]
    )
    high_risk_tlds: list[str] = field(
        default_factory=lambda: [
            ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf",
            ".gq", ".icu", ".buzz", ".vip", ".cfd", ".sbs",
        ]
    )
    protected_brands: list[str] = field(
        default_factory=lambda: [
            "telegram", "botfather", "fragment", "safeguard", "tonkeeper",
            "binance", "coinbase", "metamask", "bkash", "nagad",
        ]
    )
    block_external_telegram_invites_for_non_admins: bool = True


@dataclass
class RateLimitsConfig:
    global_requests_per_second: float = 25.0
    per_chat_messages_per_minute: int = 18
    delete_batch_window_ms: int = 150
    max_delete_batch_size: int = 100
    max_retries: int = 3


@dataclass
class SemanticAIConfig:
    enabled: bool = False
    provider: str = "openai_compatible"  # openai_compatible | gemini
    api_base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    timeout_seconds: float = 3.0


@dataclass
class BotConfig:
    bot_token: str = ""
    api_base_url: str = "https://api.telegram.org"  # Override for Local Bot API Server
    database_path: str = "data/aegistg.db"
    owner_alert_chat_id: int | None = None
    privacy_policy_url: str = "https://example.org/aegistg-privacy"
    webhook_url: str = ""
    webhook_host: str = "0.0.0.0"
    webhook_port: int = 8443
    webhook_secret_token: str = ""
    download_media_for_inspection: bool = True
    max_media_download_bytes: int = 5 * 1024 * 1024  # 5 MB safety cap
    thresholds: ThresholdsConfig = field(default_factory=ThresholdsConfig)
    raid: RaidConfig = field(default_factory=RaidConfig)
    edit_bait: EditBaitConfig = field(default_factory=EditBaitConfig)
    channel_guard: ChannelGuardConfig = field(default_factory=ChannelGuardConfig)
    reputation: ReputationConfig = field(default_factory=ReputationConfig)
    media: MediaConfig = field(default_factory=MediaConfig)
    urls: UrlsConfig = field(default_factory=UrlsConfig)
    rate_limits: RateLimitsConfig = field(default_factory=RateLimitsConfig)
    semantic_ai: SemanticAIConfig = field(default_factory=SemanticAIConfig)


def _merge_dataclass(obj: Any, data: dict[str, Any] | None) -> None:
    if not data:
        return
    for key, value in data.items():
        if hasattr(obj, key) and value is not None:
            setattr(obj, key, value)


def load_config(policy_path: str | Path | None = None) -> BotConfig:
    """Load BotConfig from YAML policy file + environment variable overrides."""
    cfg = BotConfig()

    if policy_path is None:
        default_file = Path(__file__).resolve().parent.parent / "config" / "default_policy.yaml"
        if default_file.exists():
            policy_path = default_file

    if policy_path is not None:
        path = Path(policy_path)
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            _merge_dataclass(cfg.thresholds, raw.get("thresholds"))
            _merge_dataclass(cfg.raid, raw.get("raid"))
            _merge_dataclass(cfg.edit_bait, raw.get("edit_bait"))
            _merge_dataclass(cfg.channel_guard, raw.get("channel_guard"))
            _merge_dataclass(cfg.reputation, raw.get("reputation"))
            _merge_dataclass(cfg.media, raw.get("media"))
            _merge_dataclass(cfg.urls, raw.get("urls"))
            _merge_dataclass(cfg.rate_limits, raw.get("rate_limits"))

    # Environment variable overrides
    cfg.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", cfg.bot_token).strip()
    cfg.api_base_url = os.getenv("TELEGRAM_API_BASE_URL", cfg.api_base_url).rstrip("/")
    cfg.database_path = os.getenv("AEGIS_DB_PATH", cfg.database_path)
    cfg.privacy_policy_url = os.getenv("AEGIS_PRIVACY_POLICY_URL", cfg.privacy_policy_url)
    cfg.webhook_url = os.getenv("AEGIS_WEBHOOK_URL", cfg.webhook_url).strip()
    cfg.webhook_host = os.getenv("AEGIS_WEBHOOK_HOST", cfg.webhook_host)
    cfg.webhook_port = int(os.getenv("AEGIS_WEBHOOK_PORT", str(cfg.webhook_port)))
    cfg.webhook_secret_token = os.getenv("AEGIS_WEBHOOK_SECRET", cfg.webhook_secret_token).strip()

    alert_env = os.getenv("AEGIS_OWNER_ALERT_CHAT_ID", "").strip()
    if alert_env:
        cfg.owner_alert_chat_id = int(alert_env)

    if os.getenv("AEGIS_CAS_ENABLED", "").lower() in {"1", "true", "yes"}:
        cfg.reputation.cas_enabled = True

    ai_key = os.getenv("AEGIS_AI_API_KEY", "").strip()
    if ai_key:
        cfg.semantic_ai.enabled = True
        cfg.semantic_ai.api_key = ai_key
        cfg.semantic_ai.provider = os.getenv("AEGIS_AI_PROVIDER", cfg.semantic_ai.provider)
        cfg.semantic_ai.api_base_url = os.getenv("AEGIS_AI_BASE_URL", cfg.semantic_ai.api_base_url).rstrip("/")
        cfg.semantic_ai.model = os.getenv("AEGIS_AI_MODEL", cfg.semantic_ai.model)

    return cfg
