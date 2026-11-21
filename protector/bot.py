"""AegisTG Bot Update Router, Enforcement Executor & Admin Command Controller."""

from __future__ import annotations

import asyncio
import html
import json
import logging
import time
from typing import Any

from protector.analyzers.media_guard import compute_dhash
from protector.auditor import SecurityAuditor
from protector.config import BotConfig
from protector.engine import ProtectionEngine
from protector.models import (
    ChatType,
    EntityInfo,
    EvaluationResult,
    EventType,
    MediaInfo,
    RaidState,
    TelegramEvent,
    VerdictAction,
)
from protector.storage import Storage
from protector.telegram_client import TelegramAPIClient, TelegramAPIError

logger = logging.getLogger("aegistg.bot")

ALLOWED_UPDATES: list[str] = [
    "message",
    "edited_message",
    "channel_post",
    "edited_channel_post",
    "chat_member",
    "my_chat_member",
    "chat_join_request",
    "callback_query",
]

LOCKDOWN_PERMISSIONS: dict[str, bool] = {
    "can_send_messages": False,
    "can_send_audios": False,
    "can_send_documents": False,
    "can_send_photos": False,
    "can_send_videos": False,
    "can_send_video_notes": False,
    "can_send_voice_notes": False,
    "can_send_polls": False,
    "can_send_other_messages": False,
    "can_add_web_page_previews": False,
    "can_change_info": False,
    "can_invite_users": False,
    "can_pin_messages": False,
}

MUTED_USER_PERMISSIONS: dict[str, bool] = {
    "can_send_messages": False,
    "can_send_audios": False,
    "can_send_documents": False,
    "can_send_photos": False,
    "can_send_videos": False,
    "can_send_video_notes": False,
    "can_send_voice_notes": False,
    "can_send_polls": False,
    "can_send_other_messages": False,
    "can_add_web_page_previews": False,
}


class AegisTGBot:
    """Main asynchronous Telegram Group & Channel Protection Bot."""

    def __init__(
        self,
        config: BotConfig,
        storage: Storage | None = None,
        client: TelegramAPIClient | None = None,
    ) -> None:
        self.config = config
        self.storage = storage or Storage(config.database_path)
        self.client = client or TelegramAPIClient(
            bot_token=config.bot_token,
            api_base_url=config.api_base_url,
            rate_limits=config.rate_limits,
        )
        self.engine = ProtectionEngine(config, self.storage)
        self.auditor = SecurityAuditor(self.storage)

        self.bot_user_id: int = 0
        self.bot_username: str = ""
        # Cache chat admin IDs with 120s TTL: chat_id -> (expires_at, set[user_id])
        self._admin_cache: dict[int, tuple[float, set[int]]] = {}
        self._running = False

    async def initialize(self) -> None:
        me = await self.client.get_me()
        self.bot_user_id = int(me["id"])
        self.bot_username = str(me.get("username", ""))
        await self.client.set_my_commands(
            [
                {"command": "status", "description": "Protection status & 24h threat summary"},
                {"command": "audit", "description": "Run 0-100 Group/Channel Security Posture Audit"},
                {"command": "draft", "description": "Pre-publish Channel compliance scan"},
                {"command": "lockdown", "description": "Activate emergency anti-raid lockdown"},
                {"command": "unlock", "description": "Lift lockdown and restore chat permissions"},
                {"command": "strict_channel", "description": "Toggle auto-quarantine for channel posts"},
                {"command": "allow_domain", "description": "Whitelist a trusted domain for this chat"},
                {"command": "set_alert_chat", "description": "Route security alerts to this chat"},
                {"command": "export_audit", "description": "Export compliance proof for abuse@telegram.org"},
                {"command": "privacy", "description": "View Bot Privacy Policy (Telegram ToS Sec 4)"},
            ]
        )
        logger.info("AegisTG initialized as @%s (id=%s)", self.bot_username, self.bot_user_id)

    async def run_polling(self) -> None:
        await self.initialize()
        await self.client.delete_webhook(drop_pending_updates=False)
        self._running = True
        offset: int | None = None
        last_prune = time.time()
        logger.info("Starting Long Polling with allowed_updates=%s", ALLOWED_UPDATES)

        while self._running:
            try:
                updates = await self.client.get_updates(
                    offset=offset, timeout=25, allowed_updates=ALLOWED_UPDATES
                )
                for upd in updates:
                    offset = int(upd["update_id"]) + 1
                    asyncio.create_task(self.handle_update(upd))
                if time.time() - last_prune > 3600:
                    self.storage.prune_expired_snapshots(self.config.edit_bait.snapshot_ttl_days)
                    last_prune = time.time()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Polling loop error: %s", exc)
                await asyncio.sleep(2.0)

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Update Router
    # ------------------------------------------------------------------
    async def handle_update(self, update: dict[str, Any]) -> EvaluationResult | None:
        try:
            if "chat_join_request" in update:
                await self._handle_join_request(update["chat_join_request"])
                return None

            if "my_chat_member" in update:
                await self._handle_my_chat_member(update["my_chat_member"])
                return None

            if "chat_member" in update:
                await self._handle_chat_member(update["chat_member"])
                return None

            if "callback_query" in update:
                await self._handle_callback_query(update["callback_query"])
                return None

            for key, etype in (
                ("message", EventType.MESSAGE),
                ("edited_message", EventType.EDITED_MESSAGE),
                ("channel_post", EventType.CHANNEL_POST),
                ("edited_channel_post", EventType.EDITED_CHANNEL_POST),
            ):
                if key in update:
                    return await self._handle_message_like(update[key], etype)
        except Exception as exc:
            logger.exception("Unhandled error processing update %s: %s", update.get("update_id"), exc)
        return None

    # ------------------------------------------------------------------
    # Message / Edited Message / Channel Post Handler
    # ------------------------------------------------------------------
    async def _handle_message_like(
        self, msg: dict[str, Any], event_type: EventType
    ) -> EvaluationResult | None:
        chat = msg.get("chat") or {}
        chat_id = int(chat["id"])
        chat_type = ChatType(chat.get("type", "private"))

        # Ensure chat is registered in storage
        chat_cfg = self.storage.get_chat_config(chat_id)
        if chat_cfg.title != chat.get("title", "") and chat.get("title"):
            chat_cfg.title = chat["title"]
            chat_cfg.chat_type = chat_type.value
            self.storage.upsert_chat_config(chat_cfg)

        # Handle commands first (only on non-edited messages)
        text = msg.get("text") or msg.get("caption") or ""
        if event_type == EventType.MESSAGE and text.startswith("/"):
            handled = await self._handle_command(msg, text)
            if handled:
                return None

        # Ignore private chat non-command messages (treat as draft check if sent to bot DM!)
        if chat_type == ChatType.PRIVATE:
            if text.strip():
                await self._run_draft_check(chat_id, msg.get("message_id"), text, msg)
            return None

        # Ignore messages sent by the bot itself
        from_user = msg.get("from") or {}
        user_id = from_user.get("id")
        if user_id is not None and int(user_id) == self.bot_user_id:
            return None

        # Check admin status for group messages
        is_admin = False
        is_anon_admin = False
        sender_chat = msg.get("sender_chat") or {}
        sender_chat_id = int(sender_chat["id"]) if sender_chat.get("id") is not None else None

        if sender_chat_id == chat_id:
            is_admin = True
            is_anon_admin = True
        elif user_id is not None and chat_type in {ChatType.GROUP, ChatType.SUPERGROUP}:
            is_admin = await self._is_user_admin(chat_id, int(user_id))
        elif chat_type == ChatType.CHANNEL:
            is_admin = True

        # Parse media & optionally download small media bytes for magic-byte / perceptual dHash
        media = await self._parse_media(msg)

        # Build unified TelegramEvent
        entities = self._parse_entities(msg.get("entities") or msg.get("caption_entities") or [])
        event = TelegramEvent(
            event_type=event_type,
            chat_id=chat_id,
            chat_type=chat_type,
            timestamp=float(msg.get("edit_date") or msg.get("date") or time.time()),
            message_id=msg.get("message_id"),
            user_id=int(user_id) if user_id is not None else None,
            username=from_user.get("username"),
            full_name=f"{from_user.get('first_name', '')} {from_user.get('last_name', '')}".strip(),
            is_bot=bool(from_user.get("is_bot", False)),
            is_admin=is_admin,
            is_anonymous_admin=is_anon_admin,
            sender_chat_id=sender_chat_id,
            sender_chat_title=sender_chat.get("title"),
            linked_chat_id=chat_cfg.linked_parent_channel_id,
            is_direct_messages=bool(chat.get("is_direct_messages", False)),
            is_forwarded=bool(msg.get("forward_origin") or msg.get("forward_date")),
            via_bot_id=(msg.get("via_bot") or {}).get("id"),
            text=text,
            entities=entities,
            media=media,
            edit_date=float(msg["edit_date"]) if msg.get("edit_date") else None,
            original_date=float(msg["date"]) if msg.get("date") else None,
            raw_update=msg,
        )

        # Evaluate through the 9-Layer Protection Engine
        result = await self.engine.evaluate(event)

        # Execute Enforcement Plan
        await self._execute_verdict(event, result)
        return result

    async def _execute_verdict(self, event: TelegramEvent, result: EvaluationResult) -> None:
        if result.action == VerdictAction.ALLOW:
            return

        chat_id = event.chat_id
        msg_id = event.message_id

        # 1. Delete Violating Message / Quarantine Channel Post
        if msg_id is not None and result.action in {
            VerdictAction.DELETE_ONLY,
            VerdictAction.DELETE_RESTRICT,
            VerdictAction.DELETE_BAN,
            VerdictAction.HARD_BLOCK_FEDBAN,
            VerdictAction.QUARANTINE_CHANNEL_POST,
        }:
            await self.client.queue_delete_message(chat_id, msg_id)

        # 2. Ban Spoofed Sender Channel (banChatSenderChat)
        if result.ban_sender_chat and event.sender_chat_id is not None:
            try:
                await self.client.ban_chat_sender_chat(chat_id, event.sender_chat_id)
            except TelegramAPIError as exc:
                logger.warning("Failed banChatSenderChat(%s, %s): %s", chat_id, event.sender_chat_id, exc)

        # 3. Ban or Restrict Offending User
        elif event.user_id is not None and not event.is_admin:
            if result.action in {VerdictAction.DELETE_BAN, VerdictAction.HARD_BLOCK_FEDBAN}:
                try:
                    await self.client.ban_chat_member(
                        chat_id=chat_id,
                        user_id=event.user_id,
                        revoke_messages=result.revoke_messages,
                    )
                except TelegramAPIError as exc:
                    logger.warning("Failed banChatMember(%s, %s): %s", chat_id, event.user_id, exc)
            elif result.action == VerdictAction.DELETE_RESTRICT and result.restrict_seconds > 0:
                try:
                    await self.client.restrict_chat_member(
                        chat_id=chat_id,
                        user_id=event.user_id,
                        permissions=MUTED_USER_PERMISSIONS,
                        until_date=int(time.time()) + result.restrict_seconds,
                    )
                except TelegramAPIError as exc:
                    logger.warning("Failed restrictChatMember(%s, %s): %s", chat_id, event.user_id, exc)

        # 4. Trigger Automatic Anti-Raid Lockdown if Violation Threshold Breached
        if result.trigger_lockdown and event.chat_type in {ChatType.GROUP, ChatType.SUPERGROUP}:
            await self._activate_lockdown(chat_id, reason="Automatic anti-raid violation threshold breached")

        # 5. Send Real-Time Owner Security Alert Card
        if result.alert_owner or result.trigger_lockdown:
            await self._send_owner_alert(event, result)

    # ------------------------------------------------------------------
    # Raid Lockdown & Permission Snapshot/Restore
    # ------------------------------------------------------------------
    async def _activate_lockdown(self, chat_id: int, reason: str) -> None:
        cfg = self.storage.get_chat_config(chat_id)
        try:
            # Snapshot original ChatPermissions before restricting so /unlock restores exact settings!
            if not cfg.saved_permissions_json:
                info = await self.client.get_chat(chat_id)
                if info.get("permissions"):
                    cfg.saved_permissions_json = json.dumps(info["permissions"])
            await self.client.set_chat_permissions(chat_id, LOCKDOWN_PERMISSIONS)
            cfg.raid_state = RaidState.LOCKDOWN.value
            self.storage.upsert_chat_config(cfg)
            self.engine.behavioral.set_raid_state(chat_id, RaidState.LOCKDOWN, time.time())
            logger.warning("LOCKDOWN activated in chat %s: %s", chat_id, reason)
            await self._notify_alert_chat(
                chat_id,
                f"<b>EMERGENCY RAID LOCKDOWN ACTIVATED</b>\n"
                f"Chat ID: <code>{chat_id}</code>\n"
                f"Reason: {html.escape(reason)}\n"
                f"Group switched to read-only. Use <code>/unlock</code> when the raid subsides.",
            )
        except TelegramAPIError as exc:
            logger.warning("Failed to activate lockdown in chat %s: %s", chat_id, exc)

    async def _lift_lockdown(self, chat_id: int) -> bool:
        cfg = self.storage.get_chat_config(chat_id)
        restored = (
            json.loads(cfg.saved_permissions_json)
            if cfg.saved_permissions_json
            else {
                "can_send_messages": True,
                "can_send_photos": True,
                "can_send_videos": True,
                "can_send_documents": True,
                "can_send_audios": True,
                "can_send_voice_notes": True,
                "can_send_video_notes": True,
                "can_send_polls": True,
                "can_send_other_messages": False,
                "can_add_web_page_previews": False,
            }
        )
        try:
            await self.client.set_chat_permissions(chat_id, restored)
            cfg.raid_state = RaidState.NORMAL.value
            cfg.saved_permissions_json = None
            self.storage.upsert_chat_config(cfg)
            self.engine.behavioral.set_raid_state(chat_id, RaidState.NORMAL, time.time())
            return True
        except TelegramAPIError as exc:
            logger.warning("Failed to unlock chat %s: %s", chat_id, exc)
            return False

    # ------------------------------------------------------------------
    # Join Requests & Membership / Admin Change Watchdog
    # ------------------------------------------------------------------
    async def _handle_join_request(self, req: dict[str, Any]) -> None:
        chat = req.get("chat") or {}
        user = req.get("from") or {}
        chat_id = int(chat["id"])
        user_id = int(user["id"])
        now = float(req.get("date") or time.time())
        cfg = self.storage.get_chat_config(chat_id)

        raid_state, triggered_lockdown = self.engine.behavioral.record_join(chat_id, now)
        if triggered_lockdown:
            await self._activate_lockdown(chat_id, reason="Massive join-request flood detected")

        # 1. Instant Decline if Federation-Banned or during active LOCKDOWN
        if self.storage.get_federation_ban(user_id, cfg.federation_id):
            await self.client.decline_chat_join_request(chat_id, user_id)
            return
        if raid_state == RaidState.LOCKDOWN:
            await self.client.decline_chat_join_request(chat_id, user_id)
            return

        # 2. Check CAS if enabled
        if self.config.reputation.cas_enabled:
            is_cas = await self.engine.reputation._check_cas(user_id)
            if is_cas:
                await self.client.decline_chat_join_request(chat_id, user_id)
                return

        # 3. Interactive Verification Gate or Auto-Approve
        if cfg.require_join_verification or raid_state == RaidState.ELEVATED:
            user_chat_id = int(req.get("user_chat_id") or user_id)
            try:
                await self.client.send_message(
                    chat_id=user_chat_id,
                    text=(
                        f"<b>Anti-Raid Verification</b>\n"
                        f"Tap below to verify you are human and join <b>{html.escape(chat.get('title', 'this group'))}</b>."
                    ),
                    reply_markup={
                        "inline_keyboard": [
                            [
                                {
                                    "text": "Verify & Join",
                                    "callback_data": f"verify:{chat_id}:{user_id}",
                                }
                            ]
                        ]
                    },
                )
            except TelegramAPIError:
                pass
        else:
            await self.client.approve_chat_join_request(chat_id, user_id)

    async def _handle_callback_query(self, cb: dict[str, Any]) -> None:
        data = str(cb.get("data") or "")
        from_user = cb.get("from") or {}
        cb_id = str(cb["id"])
        if data.startswith("verify:"):
            parts = data.split(":")
            if len(parts) == 3:
                target_chat = int(parts[1])
                expected_user = int(parts[2])
                if int(from_user["id"]) == expected_user:
                    try:
                        await self.client.approve_chat_join_request(target_chat, expected_user)
                        await self.client.answer_callback_query(cb_id, "Verified! Welcome aboard.")
                        return
                    except TelegramAPIError:
                        await self.client.answer_callback_query(
                            cb_id, "Request already processed or expired.", show_alert=True
                        )
                        return
        await self.client.answer_callback_query(cb_id)

    async def _handle_chat_member(self, update: dict[str, Any]) -> None:
        chat = update.get("chat") or {}
        chat_id = int(chat["id"])
        old_status = (update.get("old_chat_member") or {}).get("status", "")
        new_member = update.get("new_chat_member") or {}
        new_status = new_member.get("status", "")
        target_user = new_member.get("user") or {}
        actor = update.get("from") or {}
        now = float(update.get("date") or time.time())

        # Invalidate admin cache whenever roles change
        if old_status != new_status and (
            old_status in {"administrator", "creator"} or new_status in {"administrator", "creator"}
        ):
            self._admin_cache.pop(chat_id, None)
            await self._notify_alert_chat(
                chat_id,
                f"<b>ADMIN ROLE CHANGE DETECTED</b>\n"
                f"Chat: <b>{html.escape(chat.get('title', str(chat_id)))}</b>\n"
                f"Target: <code>{target_user.get('id')}</code> (@{target_user.get('username') or 'no_user'})\n"
                f"Change: <code>{old_status}</code> -> <code>{new_status}</code>\n"
                f"Actor: <code>{actor.get('id')}</code> (@{actor.get('username') or 'no_user'})",
            )

        # Member Joined -> Feed Raid State Machine & Pre-Check Federation Ban!
        if old_status in {"left", "kicked"} and new_status in {"member", "restricted"}:
            uid = int(target_user["id"])
            cfg = self.storage.get_chat_config(chat_id)
            if self.storage.get_federation_ban(uid, cfg.federation_id):
                try:
                    await self.client.ban_chat_member(chat_id, uid, revoke_messages=True)
                except TelegramAPIError:
                    pass
                return

            # Initialize fresh join timestamp for New-Member Sandbox
            self.storage.get_user_reputation(
                chat_id, uid, default_trust=self.config.reputation.initial_trust_score, now=now
            )
            _, triggered_lockdown = self.engine.behavioral.record_join(chat_id, now)
            if triggered_lockdown:
                await self._activate_lockdown(chat_id, reason="Rapid coordinated member join raid")

    async def _handle_my_chat_member(self, update: dict[str, Any]) -> None:
        chat = update.get("chat") or {}
        chat_id = int(chat["id"])
        new_status = (update.get("new_chat_member") or {}).get("status", "")
        cfg = self.storage.get_chat_config(chat_id)
        cfg.chat_type = str(chat.get("type", cfg.chat_type))
        cfg.title = str(chat.get("title", cfg.title))
        cfg.enabled = new_status in {"administrator", "member"}
        self.storage.upsert_chat_config(cfg)
        self._admin_cache.pop(chat_id, None)
        logger.info("Bot membership updated in chat %s (%s): %s", chat_id, cfg.title, new_status)

    # ------------------------------------------------------------------
    # Admin & Owner Commands
    # ------------------------------------------------------------------
    async def _handle_command(self, msg: dict[str, Any], text: str) -> bool:
        chat = msg["chat"]
        chat_id = int(chat["id"])
        chat_type = ChatType(chat.get("type", "private"))
        from_user = msg.get("from") or {}
        user_id = from_user.get("id")

        cmd_token = text.split()[0].split("@")[0].lower()
        args = text.split()[1:]

        if cmd_token in {"/start", "/help"}:
            await self.client.send_message(
                chat_id,
                "<b>AegisTG — Intelligent Telegram Group & Channel Protector</b>\n\n"
                "Protects groups, linked discussion groups, and channels against bans, raids, "
                "edit-bait sabotage, phishing, malware, and admin compromise.\n\n"
                "<b>Key Commands:</b>\n"
                "• <code>/audit</code> — 0-100 Group/Channel Security Posture Score\n"
                "• <code>/draft &lt;text&gt;</code> — Pre-publish Channel Compliance Scan\n"
                "• <code>/status</code> — Live Raid State & 24h Threat Telemetry\n"
                "• <code>/lockdown</code> / <code>/unlock</code> — Emergency Anti-Raid Mode\n"
                "• <code>/strict_channel on|off</code> — Auto-quarantine hijacked channel posts\n"
                "• <code>/allow_domain &lt;domain&gt;</code> — Whitelist trusted domain\n"
                "• <code>/ban_media</code> — Reply to scam image to ban its perceptual dHash\n"
                "• <code>/set_alert_chat</code> — Route owner alerts here\n"
                "• <code>/export_audit</code> — Export compliance proof for abuse@telegram.org\n"
                "• <code>/privacy</code> — Bot Privacy Policy",
            )
            return True

        if cmd_token == "/privacy":
            await self.client.send_message(
                chat_id,
                f"<b>AegisTG Privacy Policy</b>\n"
                f"• Message text is inspected transiently in memory only.\n"
                f"• Zero data scraping or AI/ML training (strict Telegram ToS compliance).\n"
                f"• Edit-bait hashes auto-expire in {self.config.edit_bait.snapshot_ttl_days} days.\n"
                f"• Full Policy: {html.escape(self.config.privacy_policy_url)}",
            )
            return True

        if cmd_token in {"/draft", "/check"}:
            draft_text = " ".join(args)
            if not draft_text and msg.get("reply_to_message"):
                replied = msg["reply_to_message"]
                draft_text = replied.get("text") or replied.get("caption") or ""
            if not draft_text:
                await self.client.send_message(
                    chat_id, "Usage: <code>/draft &lt;post text or link to test before publishing&gt;</code>"
                )
                return True
            await self._run_draft_check(chat_id, msg.get("message_id"), draft_text, msg)
            return True

        # Admin-gated commands for groups/channels
        if chat_type != ChatType.PRIVATE:
            if user_id is None or not await self._is_user_admin(chat_id, int(user_id)):
                return False

        if cmd_token == "/status":
            cfg = self.storage.get_chat_config(chat_id)
            stats = self.storage.get_chat_stats(chat_id, window_seconds=86400)
            raid = self.engine.behavioral.get_raid_state(chat_id, time.time())
            cats = ", ".join(f"{k}:{v}" for k, v in stats["by_category"].items()) or "None"
            await self.client.send_message(
                chat_id,
                f"<b>AegisTG Live Status</b>\n"
                f"• Protection: <code>{'ENABLED' if cfg.enabled else 'DISABLED'}</code>\n"
                f"• Raid State: <code>{raid.value}</code>\n"
                f"• Strict Channel Guard: <code>{cfg.strict_channel_guard}</code>\n"
                f"• 24h Blocked Incidents: <b>{stats['total_incidents']}</b>\n"
                f"• Categories: <code>{html.escape(cats)}</code>\n"
                f"• Avg Detection Latency: <code>{stats['avg_latency_ms']} ms</code>",
            )
            return True

        if cmd_token == "/audit":
            try:
                info = await self.client.get_chat(chat_id)
                admins = await self.client.get_chat_administrators(chat_id)
                cfg = self.storage.get_chat_config(chat_id)
                report = self.auditor.audit_chat_metadata(info, admins, self.bot_user_id, cfg)
                await self.client.send_message(chat_id, self.auditor.format_audit_report(report))
            except TelegramAPIError as exc:
                await self.client.send_message(chat_id, f"Audit failed: {html.escape(str(exc))}")
            return True

        if cmd_token == "/lockdown":
            await self._activate_lockdown(chat_id, reason="Manual admin /lockdown command")
            await self.client.send_message(chat_id, "Emergency Lockdown ACTIVATED. Group is now read-only.")
            return True

        if cmd_token == "/unlock":
            ok = await self._lift_lockdown(chat_id)
            await self.client.send_message(
                chat_id,
                "Lockdown lifted and original permissions restored."
                if ok
                else "Could not restore permissions — verify bot has Restrict Members permission.",
            )
            return True

        if cmd_token == "/strict_channel" and args:
            cfg = self.storage.get_chat_config(chat_id)
            cfg.strict_channel_guard = args[0].lower() in {"on", "true", "1", "yes"}
            self.storage.upsert_chat_config(cfg)
            await self.client.send_message(
                chat_id, f"Strict Channel Auto-Quarantine set to <code>{cfg.strict_channel_guard}</code>."
            )
            return True

        if cmd_token == "/allow_domain" and args:
            domain = args[0].lower().strip()
            cfg = self.storage.get_chat_config(chat_id)
            if domain not in cfg.allowlist_domains:
                cfg.allowlist_domains.append(domain)
                self.storage.upsert_chat_config(cfg)
            await self.client.send_message(chat_id, f"Domain <code>{html.escape(domain)}</code> whitelisted.")
            return True

        if cmd_token == "/set_alert_chat":
            target_id = int(args[0]) if args and args[0].lstrip("-").isdigit() else chat_id
            cfg = self.storage.get_chat_config(chat_id)
            cfg.alert_chat_id = target_id
            self.storage.upsert_chat_config(cfg)
            await self.client.send_message(
                chat_id, f"Owner Security Alert Chat set to <code>{target_id}</code>."
            )
            return True

        if cmd_token == "/fedban" and args and args[0].lstrip("-").isdigit():
            target_uid = int(args[0])
            reason = " ".join(args[1:]) or "Manual admin Federation ban"
            cfg = self.storage.get_chat_config(chat_id)
            self.storage.add_federation_ban(
                entity_id=target_uid,
                reason=reason,
                category="REPUTATION_FEDBAN",
                source_chat_id=chat_id,
                federation_id=cfg.federation_id,
            )
            await self.client.send_message(
                chat_id, f"Entity <code>{target_uid}</code> added to Federation Ban List."
            )
            return True

        if cmd_token == "/fedunban" and args and args[0].lstrip("-").isdigit():
            target_uid = int(args[0])
            cfg = self.storage.get_chat_config(chat_id)
            removed = self.storage.remove_federation_ban(target_uid, cfg.federation_id)
            await self.client.send_message(
                chat_id,
                f"Entity <code>{target_uid}</code> removed from Federation Ban List."
                if removed
                else f"Entity <code>{target_uid}</code> was not Federation-banned.",
            )
            return True

        if cmd_token == "/ban_media" and msg.get("reply_to_message"):
            media = await self._parse_media(msg["reply_to_message"])
            if media and media.raw_bytes:
                dhash = compute_dhash(media.raw_bytes)
                if dhash is not None:
                    reason = " ".join(args) or "Admin-banned scam/raid visual flyer"
                    self.storage.add_banned_media_hash(dhash, "SCAM_PHISHING_SAFEGUARD", reason)
                    await self.client.send_message(
                        chat_id,
                        f"Perceptual dHash <code>{dhash:016x}</code> permanently banned across all protected chats.",
                    )
                    return True
            await self.client.send_message(chat_id, "Reply to a photo/image message to ban its perceptual hash.")
            return True

        if cmd_token == "/export_audit":
            pack_json = self.auditor.format_appeal_json(chat_id, days=30)
            await self.client.send_message(
                chat_id,
                f"<b>Appeal Forensics Pack (30d)</b>\n<pre>{html.escape(pack_json[:3600])}</pre>",
            )
            return True

        if cmd_token == "/purge_chat_data":
            self.storage.purge_chat_data(chat_id)
            await self.client.send_message(chat_id, "All stored AegisTG security metadata for this chat has been erased.")
            return True

        return False

    async def _run_draft_check(
        self, chat_id: int, reply_to: int | None, draft_text: str, raw_msg: dict[str, Any]
    ) -> None:
        ev = TelegramEvent(
            event_type=EventType.DRAFT_CHECK,
            chat_id=chat_id,
            chat_type=ChatType.CHANNEL,
            timestamp=time.time(),
            text=draft_text,
            entities=self._parse_entities(raw_msg.get("entities") or []),
            is_admin=True,
        )
        res = await self.engine.evaluate(ev)
        badge = (
            "SAFE TO PUBLISH"
            if res.action == VerdictAction.ALLOW
            else ("REVIEW WARNING" if res.action == VerdictAction.WARN_MONITOR else "HIGH BAN RISK — DO NOT PUBLISH")
        )
        details = "\n".join(f"• [{s.score}] {html.escape(s.reason)}" for s in res.signals) or "• No Telegram ToS risk signals detected."
        await self.client.send_message(
            chat_id=chat_id,
            reply_to_message_id=reply_to,
            text=(
                f"<b>Pre-Publish Channel Compliance Scan</b>\n"
                f"Verdict: <b>{badge}</b>\n"
                f"Risk Score: <code>{res.risk_score}/100</code> ({res.latency_ms} ms)\n\n"
                f"{details}"
            ),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def _is_user_admin(self, chat_id: int, user_id: int) -> bool:
        now = time.monotonic()
        cached = self._admin_cache.get(chat_id)
        if cached and cached[0] > now:
            return user_id in cached[1]
        try:
            admins = await self.client.get_chat_administrators(chat_id)
            ids = {int(a["user"]["id"]) for a in admins if a.get("user")}
            self._admin_cache[chat_id] = (now + 120.0, ids)
            return user_id in ids
        except TelegramAPIError:
            return False

    def _parse_entities(self, raw_entities: list[dict[str, Any]]) -> list[EntityInfo]:
        out: list[EntityInfo] = []
        for e in raw_entities:
            out.append(
                EntityInfo(
                    type=str(e.get("type", "")),
                    offset=int(e.get("offset", 0)),
                    length=int(e.get("length", 0)),
                    url=e.get("url"),
                    user_id=(e.get("user") or {}).get("id"),
                )
            )
        return out

    async def _parse_media(self, msg: dict[str, Any]) -> MediaInfo | None:
        media: MediaInfo | None = None
        if msg.get("document"):
            doc = msg["document"]
            media = MediaInfo(
                media_type="document",
                file_id=doc.get("file_id"),
                file_unique_id=doc.get("file_unique_id"),
                file_name=doc.get("file_name"),
                mime_type=doc.get("mime_type"),
                file_size=doc.get("file_size"),
            )
        elif msg.get("photo"):
            # Pick medium thumbnail (fast to download & ideal for 8x8 dHash!)
            photos = msg["photo"]
            chosen = photos[min(1, len(photos) - 1)]
            media = MediaInfo(
                media_type="photo",
                file_id=chosen.get("file_id"),
                file_unique_id=chosen.get("file_unique_id"),
                file_size=chosen.get("file_size"),
            )
        elif msg.get("video"):
            vid = msg["video"]
            media = MediaInfo(
                media_type="video",
                file_id=vid.get("file_id"),
                file_unique_id=vid.get("file_unique_id"),
                file_name=vid.get("file_name"),
                mime_type=vid.get("mime_type"),
                file_size=vid.get("file_size"),
            )

        if (
            media
            and media.file_id
            and self.config.download_media_for_inspection
            and self.config.bot_token
            and media.media_type in {"photo", "document"}
            and (media.file_size or 0) <= self.config.max_media_download_bytes
        ):
            try:
                media.raw_bytes = await self.client.download_file_bytes(
                    media.file_id, max_bytes=self.config.max_media_download_bytes
                )
            except Exception:
                pass
        return media

    async def _send_owner_alert(self, event: TelegramEvent, result: EvaluationResult) -> None:
        cat = result.primary_category.value if result.primary_category else "POLICY_RISK"
        actor = event.sender_chat_id if result.ban_sender_chat else event.user_id
        text = (
            f"<b>AegisTG Security Alert</b>\n"
            f"• Chat: <code>{event.chat_id}</code> ({event.chat_type.value})\n"
            f"• Event: <code>{event.event_type.value}</code>\n"
            f"• Category: <b>{cat}</b> | Risk: <b>{result.risk_score}/100</b>\n"
            f"• Action: <code>{result.action.value}</code>\n"
            f"• Actor ID: <code>{actor}</code>\n"
            f"• Summary: {html.escape(result.summary[:300])}"
        )
        await self._notify_alert_chat(event.chat_id, text)

    async def _notify_alert_chat(self, source_chat_id: int, html_text: str) -> None:
        cfg = self.storage.get_chat_config(source_chat_id)
        target = cfg.alert_chat_id or self.config.owner_alert_chat_id
        if target is None:
            return
        try:
            await self.client.send_message(target, html_text)
        except TelegramAPIError as exc:
            logger.warning("Failed sending owner alert to %s: %s", target, exc)
