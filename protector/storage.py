"""SQLite WAL persistence layer for AegisTG Protector.

Stores minimal privacy-compliant security state:
- Chat protection configs & pre-lockdown permission snapshots
- Behavioral user trust ledger & strikes
- Local Federation ban table (users & spoofed sender_chats)
- Short-lived message structural snapshots (Edit-Bait detection, TTL-pruned)
- Banned media perceptual hashes (64-bit dHash integers)
- CAS threat-intel cache
- Privacy-redacted incident audit log (for owner alerts & abuse@telegram.org appeal packs)
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from protector.models import (
    ChatConfig,
    IncidentRecord,
    MessageSnapshot,
    UserReputation,
)


class Storage:
    """Thread-safe SQLite WAL repository."""

    def __init__(self, db_path: str | Path = "data/aegistg.db") -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA foreign_keys=ON;")

            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS chat_configs (
                    chat_id INTEGER PRIMARY KEY,
                    chat_type TEXT NOT NULL DEFAULT 'supergroup',
                    title TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    alert_chat_id INTEGER,
                    linked_parent_channel_id INTEGER,
                    strict_channel_guard INTEGER NOT NULL DEFAULT 0,
                    require_join_verification INTEGER NOT NULL DEFAULT 0,
                    allowlist_domains_json TEXT NOT NULL DEFAULT '[]',
                    raid_state TEXT NOT NULL DEFAULT 'NORMAL',
                    saved_permissions_json TEXT,
                    federation_id TEXT NOT NULL DEFAULT 'default',
                    updated_at REAL NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS user_reputation (
                    chat_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    trust_score INTEGER NOT NULL DEFAULT 50,
                    joined_at REAL NOT NULL DEFAULT 0,
                    clean_messages INTEGER NOT NULL DEFAULT 0,
                    strikes INTEGER NOT NULL DEFAULT 0,
                    last_violation_at REAL,
                    PRIMARY KEY (chat_id, user_id)
                );

                CREATE TABLE IF NOT EXISTS federation_bans (
                    federation_id TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    entity_type TEXT NOT NULL DEFAULT 'user',
                    reason TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source_chat_id INTEGER,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (federation_id, entity_id)
                );

                CREATE TABLE IF NOT EXISTS message_snapshots (
                    chat_id INTEGER NOT NULL,
                    message_id INTEGER NOT NULL,
                    user_id INTEGER,
                    content_sha256 TEXT NOT NULL,
                    token_fingerprint TEXT NOT NULL,
                    text_length INTEGER NOT NULL,
                    url_count INTEGER NOT NULL,
                    has_media INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (chat_id, message_id)
                );
                CREATE INDEX IF NOT EXISTS idx_snapshots_created ON message_snapshots(created_at);

                CREATE TABLE IF NOT EXISTS banned_media_hashes (
                    dhash_hex TEXT PRIMARY KEY,
                    dhash_int INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    added_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cas_cache (
                    user_id INTEGER PRIMARY KEY,
                    is_banned INTEGER NOT NULL,
                    offenses INTEGER NOT NULL DEFAULT 0,
                    checked_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    chat_id INTEGER NOT NULL,
                    chat_type TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor_id INTEGER,
                    sender_chat_id INTEGER,
                    message_id INTEGER,
                    primary_category TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    action_taken TEXT NOT NULL,
                    signals_json TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    redacted_preview TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_chat_ts ON incidents(chat_id, timestamp DESC);
                """
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Chat Configs
    # ------------------------------------------------------------------
    def get_chat_config(self, chat_id: int) -> ChatConfig:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM chat_configs WHERE chat_id = ?", (chat_id,)
            ).fetchone()
            if not row:
                return ChatConfig(chat_id=chat_id)
            return ChatConfig(
                chat_id=row["chat_id"],
                chat_type=row["chat_type"],
                title=row["title"],
                enabled=bool(row["enabled"]),
                alert_chat_id=row["alert_chat_id"],
                linked_parent_channel_id=row["linked_parent_channel_id"],
                strict_channel_guard=bool(row["strict_channel_guard"]),
                require_join_verification=bool(row["require_join_verification"]),
                allowlist_domains=json.loads(row["allowlist_domains_json"] or "[]"),
                raid_state=row["raid_state"],
                saved_permissions_json=row["saved_permissions_json"],
                federation_id=row["federation_id"],
            )

    def upsert_chat_config(self, cfg: ChatConfig) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO chat_configs (
                    chat_id, chat_type, title, enabled, alert_chat_id,
                    linked_parent_channel_id, strict_channel_guard,
                    require_join_verification, allowlist_domains_json,
                    raid_state, saved_permissions_json, federation_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chat_id) DO UPDATE SET
                    chat_type = excluded.chat_type,
                    title = CASE WHEN excluded.title != '' THEN excluded.title ELSE chat_configs.title END,
                    enabled = excluded.enabled,
                    alert_chat_id = excluded.alert_chat_id,
                    linked_parent_channel_id = excluded.linked_parent_channel_id,
                    strict_channel_guard = excluded.strict_channel_guard,
                    require_join_verification = excluded.require_join_verification,
                    allowlist_domains_json = excluded.allowlist_domains_json,
                    raid_state = excluded.raid_state,
                    saved_permissions_json = excluded.saved_permissions_json,
                    federation_id = excluded.federation_id,
                    updated_at = excluded.updated_at
                """,
                (
                    cfg.chat_id,
                    cfg.chat_type,
                    cfg.title,
                    int(cfg.enabled),
                    cfg.alert_chat_id,
                    cfg.linked_parent_channel_id,
                    int(cfg.strict_channel_guard),
                    int(cfg.require_join_verification),
                    json.dumps(cfg.allowlist_domains),
                    cfg.raid_state,
                    cfg.saved_permissions_json,
                    cfg.federation_id,
                    time.time(),
                ),
            )
            self._conn.commit()

    def is_chat_registered(self, chat_id: int) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM chat_configs WHERE chat_id = ? AND enabled = 1", (chat_id,)
            ).fetchone()
            return row is not None

    # ------------------------------------------------------------------
    # User Reputation Ledger
    # ------------------------------------------------------------------
    def get_user_reputation(
        self, chat_id: int, user_id: int, default_trust: int = 50, now: float | None = None
    ) -> UserReputation:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM user_reputation WHERE chat_id = ? AND user_id = ?",
                (chat_id, user_id),
            ).fetchone()
            if row:
                return UserReputation(
                    chat_id=row["chat_id"],
                    user_id=row["user_id"],
                    trust_score=row["trust_score"],
                    joined_at=row["joined_at"],
                    clean_messages=row["clean_messages"],
                    strikes=row["strikes"],
                    last_violation_at=row["last_violation_at"],
                )
            ts = now if now is not None else time.time()
            rep = UserReputation(chat_id=chat_id, user_id=user_id, trust_score=default_trust, joined_at=ts)
            self.save_user_reputation(rep)
            return rep

    def save_user_reputation(self, rep: UserReputation) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO user_reputation (
                    chat_id, user_id, trust_score, joined_at, clean_messages, strikes, last_violation_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chat_id, user_id) DO UPDATE SET
                    trust_score = excluded.trust_score,
                    joined_at = excluded.joined_at,
                    clean_messages = excluded.clean_messages,
                    strikes = excluded.strikes,
                    last_violation_at = excluded.last_violation_at
                """,
                (
                    rep.chat_id,
                    rep.user_id,
                    max(0, min(100, rep.trust_score)),
                    rep.joined_at,
                    rep.clean_messages,
                    rep.strikes,
                    rep.last_violation_at,
                ),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Federation Bans
    # ------------------------------------------------------------------
    def add_federation_ban(
        self,
        entity_id: int,
        reason: str,
        category: str,
        source_chat_id: int | None = None,
        federation_id: str = "default",
        entity_type: str = "user",
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO federation_bans (
                    federation_id, entity_id, entity_type, reason, category, source_chat_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(federation_id, entity_id) DO UPDATE SET
                    reason = excluded.reason,
                    category = excluded.category,
                    source_chat_id = excluded.source_chat_id,
                    created_at = excluded.created_at
                """,
                (federation_id, entity_id, entity_type, reason, category, source_chat_id, time.time()),
            )
            self._conn.commit()

    def get_federation_ban(
        self, entity_id: int, federation_id: str = "default"
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM federation_bans WHERE federation_id = ? AND entity_id = ?",
                (federation_id, entity_id),
            ).fetchone()
            return dict(row) if row else None

    def remove_federation_ban(self, entity_id: int, federation_id: str = "default") -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM federation_bans WHERE federation_id = ? AND entity_id = ?",
                (federation_id, entity_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Message Snapshots (Edit-Bait Detection)
    # ------------------------------------------------------------------
    def save_message_snapshot(self, snap: MessageSnapshot) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO message_snapshots (
                    chat_id, message_id, user_id, content_sha256, token_fingerprint,
                    text_length, url_count, has_media, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snap.chat_id,
                    snap.message_id,
                    snap.user_id,
                    snap.content_sha256,
                    snap.token_fingerprint,
                    snap.text_length,
                    snap.url_count,
                    int(snap.has_media),
                    snap.created_at,
                ),
            )
            self._conn.commit()

    def get_message_snapshot(self, chat_id: int, message_id: int) -> MessageSnapshot | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM message_snapshots WHERE chat_id = ? AND message_id = ?",
                (chat_id, message_id),
            ).fetchone()
            if not row:
                return None
            return MessageSnapshot(
                chat_id=row["chat_id"],
                message_id=row["message_id"],
                user_id=row["user_id"],
                content_sha256=row["content_sha256"],
                token_fingerprint=row["token_fingerprint"],
                text_length=row["text_length"],
                url_count=row["url_count"],
                has_media=bool(row["has_media"]),
                created_at=row["created_at"],
            )

    def prune_expired_snapshots(self, ttl_days: int = 7) -> int:
        cutoff = time.time() - ttl_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM message_snapshots WHERE created_at < ?", (cutoff,)
            )
            self._conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------------
    # Perceptual Media Hashes (64-bit dHash)
    # ------------------------------------------------------------------
    def add_banned_media_hash(self, dhash_int: int, category: str, reason: str) -> None:
        dhash_hex = f"{dhash_int:016x}"
        # Store signed 64-bit compatible or TEXT hex (SQLite INTEGER max is 2^63-1, so use hex as authoritative)
        signed_int = dhash_int - (1 << 64) if dhash_int >= (1 << 63) else dhash_int
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO banned_media_hashes (
                    dhash_hex, dhash_int, category, reason, added_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (dhash_hex, signed_int, category, reason, time.time()),
            )
            self._conn.commit()

    def list_banned_media_hashes(self) -> list[tuple[int, str, str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT dhash_hex, category, reason FROM banned_media_hashes"
            ).fetchall()
            return [(int(r["dhash_hex"], 16), r["category"], r["reason"]) for r in rows]

    # ------------------------------------------------------------------
    # CAS Cache
    # ------------------------------------------------------------------
    def get_cas_cache(self, user_id: int, ttl_seconds: int) -> bool | None:
        cutoff = time.time() - ttl_seconds
        with self._lock:
            row = self._conn.execute(
                "SELECT is_banned, checked_at FROM cas_cache WHERE user_id = ?", (user_id,)
            ).fetchone()
            if row and row["checked_at"] >= cutoff:
                return bool(row["is_banned"])
            return None

    def set_cas_cache(self, user_id: int, is_banned: bool, offenses: int = 0) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO cas_cache (user_id, is_banned, offenses, checked_at)
                VALUES (?, ?, ?, ?)
                """,
                (user_id, int(is_banned), offenses, time.time()),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Redacted Incident Forensics Log
    # ------------------------------------------------------------------
    def record_incident(self, inc: IncidentRecord) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, timestamp, chat_id, chat_type, event_type,
                    actor_id, sender_chat_id, message_id, primary_category,
                    risk_score, action_taken, signals_json, latency_ms, redacted_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    inc.incident_id,
                    inc.timestamp,
                    inc.chat_id,
                    inc.chat_type,
                    inc.event_type,
                    inc.actor_id,
                    inc.sender_chat_id,
                    inc.message_id,
                    inc.primary_category,
                    inc.risk_score,
                    inc.action_taken,
                    json.dumps(inc.signals_summary),
                    inc.latency_ms,
                    inc.redacted_preview,
                ),
            )
            self._conn.commit()

    def get_incidents(
        self, chat_id: int, limit: int = 100, since_ts: float | None = None
    ) -> list[IncidentRecord]:
        with self._lock:
            if since_ts is not None:
                rows = self._conn.execute(
                    """
                    SELECT * FROM incidents
                    WHERE chat_id = ? AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (chat_id, since_ts, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM incidents
                    WHERE chat_id = ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (chat_id, limit),
                ).fetchall()
            return [
                IncidentRecord(
                    incident_id=r["incident_id"],
                    timestamp=r["timestamp"],
                    chat_id=r["chat_id"],
                    chat_type=r["chat_type"],
                    event_type=r["event_type"],
                    actor_id=r["actor_id"],
                    sender_chat_id=r["sender_chat_id"],
                    message_id=r["message_id"],
                    primary_category=r["primary_category"],
                    risk_score=r["risk_score"],
                    action_taken=r["action_taken"],
                    signals_summary=json.loads(r["signals_json"] or "[]"),
                    latency_ms=r["latency_ms"],
                    redacted_preview=r["redacted_preview"],
                )
                for r in rows
            ]

    def get_chat_stats(self, chat_id: int, window_seconds: int = 86400) -> dict[str, Any]:
        since = time.time() - window_seconds
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT primary_category, action_taken, COUNT(*) as cnt, AVG(latency_ms) as avg_ms
                FROM incidents
                WHERE chat_id = ? AND timestamp >= ?
                GROUP BY primary_category, action_taken
                """,
                (chat_id, since),
            ).fetchall()
            total = 0
            by_category: dict[str, int] = {}
            by_action: dict[str, int] = {}
            latencies: list[float] = []
            for r in rows:
                cnt = int(r["cnt"])
                total += cnt
                by_category[r["primary_category"]] = by_category.get(r["primary_category"], 0) + cnt
                by_action[r["action_taken"]] = by_action.get(r["action_taken"], 0) + cnt
                if r["avg_ms"] is not None:
                    latencies.append(float(r["avg_ms"]))
            return {
                "total_incidents": total,
                "by_category": by_category,
                "by_action": by_action,
                "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
            }

    def purge_chat_data(self, chat_id: int) -> None:
        """Compliance right-to-erasure for a chat owner."""
        with self._lock:
            self._conn.execute("DELETE FROM chat_configs WHERE chat_id = ?", (chat_id,))
            self._conn.execute("DELETE FROM user_reputation WHERE chat_id = ?", (chat_id,))
            self._conn.execute("DELETE FROM message_snapshots WHERE chat_id = ?", (chat_id,))
            self._conn.execute("DELETE FROM incidents WHERE chat_id = ?", (chat_id,))
            self._conn.commit()
