"""AegisTG v2.0 Bot Update Router, Native UX Controller, Self-Healing Triage & Action Executor."""

from __future__ import annotations

import asyncio
import html
import json
import logging
import time
from typing import Any

from protector import (
    __developer__,
    __developer_telegram__,
    __developer_website__,
)
from protector.analyzers.media_guard import DecompressionBombDetected, compute_dhash
from protector.auditor import SecurityAuditor
from protector.config import BotConfig
from protector.engine import ProtectionEngine
from protector.models import (
    ChatConfig,
    ChatType,
    EntityInfo,
    EvaluationResult,
    EventType,
    MediaInfo,
    RaidState,
    TelegramEvent,
    VerdictAction,
)
from protector.security import CallbackSigner, RuntimeMetrics
from protector.storage import Storage
from protector.telegram_client import TelegramAPIClient, TelegramAPIError
from protector.ui import (
    EFFECT_CELEBRATION,
    build_emoji_captcha,
    render_audit_card,
    render_control_panel,
    render_dev_info_card,
    render_digest_card,
    render_draft_card,
    render_inline_scan_result,
    render_native_chat_picker_keyboard,
    render_owner_alert_card,
    render_welcome_card,
)

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
    "inline_query",
]

DEFAULT_GROUP_ADMIN_RIGHTS: dict[str, bool] = {
    "is_anonymous": False,
    "can_manage_chat": True,
    "can_delete_messages": True,
    "can_restrict_members": True,
    "can_invite_users": True,
    "can_promote_members": False,
    "can_change_info": False,
    "can_pin_messages": False,
    "can_manage_video_chats": False,
}

DEFAULT_CHANNEL_ADMIN_RIGHTS: dict[str, bool] = {
    "is_anonymous": False,
    "can_manage_chat": True,
    "can_post_messages": True,
    "can_edit_messages": True,
    "can_delete_messages": True,
    "can_invite_users": True,
    "can_manage_direct_messages": True,
    "can_promote_members": False,
    "can_change_info": False,
}

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

RESTORED_USER_PERMISSIONS: dict[str, bool] = {
    "can_send_messages": True,
    "can_send_audios": True,
    "can_send_documents": True,
    "can_send_photos": True,
    "can_send_videos": True,
    "can_send_video_notes": True,
    "can_send_voice_notes": True,
    "can_send_polls": True,
    "can_send_other_messages": False,
    "can_add_web_page_previews": False,
}


class AegisTGBot:
    """Main asynchronous Telegram Group & Channel Protection Bot (v2.0)."""

    def __init__(
        self,
        config: BotConfig,
        storage: Storage | None = None,
        client: TelegramAPIClient | None = None,
    ) -> None:
        self.config = config
        self.metrics = RuntimeMetrics()
        self.storage = storage or Storage(config.database_path)
        self.client = client or TelegramAPIClient(
            bot_token=config.bot_token,
            api_base_url=config.api_base_url,
            rate_limits=config.rate_limits,
            metrics=self.metrics,
        )
        self.engine = ProtectionEngine(config, self.storage, metrics=self.metrics)
        self.auditor = SecurityAuditor(self.storage)
        self.signer = CallbackSigner(config.webhook_secret_token or config.bot_token or None)

        self.bot_user_id: int = 0
        self.bot_username: str = ""
        # Cache chat admin IDs with 120s TTL: chat_id -> (expires_at, set[user_id])
        self._admin_cache: dict[int, tuple[float, set[int]]] = {}
        # Track pending captcha auto-cleanup tasks: (chat_id, user_id) -> Task
        self._pending_captchas: dict[tuple[int, int], asyncio.Task[None]] = {}
        self._running = False

    async def initialize(self) -> None:
        """Configure native Bot API profile, default admin rights, and role-scoped command menus."""
        me = await self.client.get_me()
        self.bot_user_id = int(me["id"])
        self.bot_username = str(me.get("username", ""))

        # 1. Pre-fill exact least-privilege admin rights for startgroup & startchannel onboarding
        try:
            await self.client.set_my_default_administrator_rights(
                DEFAULT_GROUP_ADMIN_RIGHTS, for_channels=False
            )
            await self.client.set_my_default_administrator_rights(
                DEFAULT_CHANNEL_ADMIN_RIGHTS, for_channels=True
            )
        except TelegramAPIError as exc:
            logger.debug("Optional setMyDefaultAdministratorRights skipped: %s", exc)

        # 2. Polish native Telegram bot profile description
        try:
            await self.client.set_my_short_description(
                "🛡 9-Layer Telegram Group & Channel Protector — Anti-Raid, Scam & Malware Shield | @drkingbd (drkingbd.cc)"
            )
            await self.client.set_my_description(
                "AegisTG protects Telegram Groups, Linked Discussion Groups, and Broadcast Channels from bans, "
                "raids, delayed edit-bait sabotage, phishing, malware, and admin hijacks — with zero clutter "
                "and strict Telegram Terms of Service & Privacy compliance.\n\n"
                f"Developer: {__developer_telegram__} | {__developer_website__}"
            )
        except TelegramAPIError as exc:
            logger.debug("Optional setMyDescription skipped: %s", exc)

        # 3. Role-Scoped Command Menus (Clean UX: members vs admins vs DM!)
        dm_commands = [
            {"command": "start", "description": "🚀 Onboarding wizard & quick setup"},
            {"command": "panel", "description": "🎛 Interactive Control Center Dashboard"},
            {"command": "connect", "description": "🔗 Native Group/Channel & Alert Chat Picker"},
            {"command": "draft", "description": "🧪 Pre-publish Channel Compliance Scan"},
            {"command": "privacy", "description": "🔒 Bot Privacy Policy (ToS Sec 4)"},
            {"command": "about", "description": "👨‍💻 About AegisTG & Developer Info"},
        ]
        member_group_commands = [
            {"command": "privacy", "description": "🔒 View Bot Privacy Policy"},
            {"command": "about", "description": "👨‍💻 About AegisTG & Developer Info"},
            {"command": "help", "description": "ℹ️ About AegisTG Protection"},
        ]
        admin_group_commands = [
            {"command": "panel", "description": "🎛 Live Interactive Control Center"},
            {"command": "audit", "description": "🔍 Run 0-100 Security Posture Audit"},
            {"command": "digest", "description": "📈 7-Day Community Protection Digest"},
            {"command": "status", "description": "⚡ Live Raid State & 24h Telemetry"},
            {"command": "draft", "description": "🧪 Pre-publish Channel Compliance Scan"},
            {"command": "lockdown", "description": "🚨 Activate Emergency Anti-Raid Lockdown"},
            {"command": "unlock", "description": "🔓 Lift Lockdown & Restore Permissions"},
            {"command": "strict_channel", "description": "🛡 Toggle Channel Auto-Quarantine"},
            {"command": "ban_media", "description": "🖼 Ban Scam Image Perceptual Hash (dHash)"},
            {"command": "allow_domain", "description": "✅ Whitelist Trusted Domain"},
            {"command": "set_alert_chat", "description": "📡 Route Security Alerts Here"},
            {"command": "export_audit", "description": "📄 Export Proof for abuse@telegram.org"},
        ]

        try:
            await self.client.set_my_commands(dm_commands, scope={"type": "all_private_chats"})
            await self.client.set_my_commands(member_group_commands, scope={"type": "all_group_chats"})
            await self.client.set_my_commands(
                admin_group_commands, scope={"type": "all_chat_administrators"}
            )
        except TelegramAPIError:
            await self.client.set_my_commands(admin_group_commands)

        logger.info("AegisTG v2.0 initialized as @%s (id=%s)", self.bot_username, self.bot_user_id)

    async def shutdown(self) -> None:
        """Gracefully drain queues, cancel timers, checkpoint WAL, and close pools."""
        self._running = False
        for task in list(self._pending_captchas.values()):
            task.cancel()
        self._pending_captchas.clear()
        await self.client.close()
        self.storage.close()
        logger.info("AegisTG shutdown complete.")

    async def run_polling(self) -> None:
        await self.initialize()
        await self.client.delete_webhook(drop_pending_updates=False)
        self._running = True
        offset: int | None = None
        last_maintenance = time.time()
        logger.info("Starting Long Polling with allowed_updates=%s", ALLOWED_UPDATES)

        try:
            while self._running:
                try:
                    updates = await self.client.get_updates(
                        offset=offset, timeout=25, allowed_updates=ALLOWED_UPDATES
                    )
                    for upd in updates:
                        offset = int(upd["update_id"]) + 1
                        asyncio.create_task(self.handle_update(upd))
                    if time.time() - last_maintenance > 3600:
                        self.storage.prune_expired_data(
                            snapshot_ttl_days=self.config.edit_bait.snapshot_ttl_days
                        )
                        last_maintenance = time.time()
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.exception("Polling loop error: %s", exc)
                    await asyncio.sleep(2.0)
        finally:
            await self.shutdown()

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Update Router
    # ------------------------------------------------------------------
    async def handle_update(self, update: dict[str, Any]) -> EvaluationResult | None:
        try:
            if "inline_query" in update:
                await self._handle_inline_query(update["inline_query"])
                return None

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
    # Inline Security Scanner (`@BotName <url or draft text>`)
    # ------------------------------------------------------------------
    async def _handle_inline_query(self, iq: dict[str, Any]) -> None:
        iq_id = str(iq["id"])
        query = str(iq.get("query") or "").strip()
        if len(query) < 4:
            await self.client.answer_inline_query(
                iq_id,
                results=[
                    {
                        "type": "article",
                        "id": "hint",
                        "title": "🛡 AegisTG Instant Security Scanner",
                        "description": "Type or paste any URL or channel draft post to scan for scams, phishing, or DMCA risk.",
                        "input_message_content": {
                            "message_text": "🛡 Use <code>@"
                            + html.escape(self.bot_username or "AegisTGBot")
                            + " &lt;url or draft&gt;</code> to scan links or channel posts inline!",
                            "parse_mode": "HTML",
                        },
                    }
                ],
                cache_time=60,
            )
            return

        ev = TelegramEvent(
            event_type=EventType.DRAFT_CHECK,
            chat_id=0,
            chat_type=ChatType.CHANNEL,
            timestamp=time.time(),
            text=query,
            is_admin=False,
        )
        res = await self.engine.evaluate(ev)
        self.metrics.inline_scans += 1
        articles = render_inline_scan_result(query, res)
        await self.client.answer_inline_query(iq_id, results=articles, cache_time=10)

    # ------------------------------------------------------------------
    # Message / Edited Message / Channel Post Handler
    # ------------------------------------------------------------------
    async def _handle_message_like(
        self, msg: dict[str, Any], event_type: EventType
    ) -> EvaluationResult | None:
        chat = msg.get("chat") or {}
        chat_id = int(chat["id"])
        chat_type = ChatType(chat.get("type", "private"))

        # Handle Native Telegram KeyboardButtonRequestChat (`chat_shared`) binding!
        if "chat_shared" in msg and chat_type == ChatType.PRIVATE:
            await self._handle_chat_shared(msg)
            return None

        # Register / keep chat title synchronized
        chat_cfg = self.storage.get_chat_config(chat_id)
        if chat.get("title") and (chat_cfg.title != chat.get("title") or chat_cfg.chat_type != chat_type.value):
            chat_cfg.title = str(chat["title"])
            chat_cfg.chat_type = chat_type.value
            self.storage.upsert_chat_config(chat_cfg)

        text = msg.get("text") or msg.get("caption") or ""
        if event_type == EventType.MESSAGE and text.startswith("/"):
            handled = await self._handle_command(msg, text)
            if handled:
                return None

        # Private DM non-command messages -> Instant Pre-Publish Compliance Scan!
        if chat_type == ChatType.PRIVATE:
            if text.strip():
                await self._run_draft_check(chat_id, msg.get("message_id"), text, msg)
            return None

        from_user = msg.get("from") or {}
        user_id = from_user.get("id")
        if user_id is not None and int(user_id) == self.bot_user_id:
            return None

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

        media = await self._parse_media(msg)
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

        result = await self.engine.evaluate(event)
        await self._execute_verdict(event, result)
        return result

    async def _handle_chat_shared(self, msg: dict[str, Any]) -> None:
        dm_chat_id = int(msg["chat"]["id"])
        shared = msg["chat_shared"]
        req_id = int(shared.get("request_id", 0))
        target_chat_id = int(shared["chat_id"])
        target_title = str(shared.get("title") or target_chat_id)

        if req_id == 103:
            # Bind as global/default Owner Alert Chat for all chats managed by this owner!
            self.config.owner_alert_chat_id = target_chat_id
            for c in self.storage.list_chat_configs(enabled_only=True):
                if c.alert_chat_id is None:
                    c.alert_chat_id = target_chat_id
                    self.storage.upsert_chat_config(c)
            await self.client.send_message(
                dm_chat_id,
                f"✅ <b>Owner Alert Chat Bound!</b>\n"
                f"Security incidents &amp; hijack alerts will route to <b>{html.escape(target_title)}</b> "
                f"(<code>{target_chat_id}</code>).",
                reply_markup={"remove_keyboard": True},
            )
            return

        # req_id 101 (Channel) or 102 (Group): register & open Control Center immediately!
        cfg = self.storage.get_chat_config(target_chat_id)
        cfg.title = target_title
        cfg.chat_type = "channel" if req_id == 101 else "supergroup"
        cfg.enabled = True
        self.storage.upsert_chat_config(cfg)

        raid = self.engine.behavioral.get_raid_state(target_chat_id, time.time())
        stats = self.storage.get_chat_stats(target_chat_id, window_seconds=86400)
        prec = self.storage.get_precision_metrics(target_chat_id)
        text, markup = render_control_panel(cfg, raid, stats, prec, self.signer, tab="overview")
        await self.client.send_message(
            dm_chat_id,
            f"✅ Connected <b>{html.escape(target_title)}</b>!\n\n{text}",
            reply_markup=markup,
        )

    async def _execute_verdict(self, event: TelegramEvent, result: EvaluationResult) -> None:
        if result.action == VerdictAction.ALLOW:
            return

        chat_id = event.chat_id
        msg_id = event.message_id

        if msg_id is not None and result.action in {
            VerdictAction.DELETE_ONLY,
            VerdictAction.DELETE_RESTRICT,
            VerdictAction.DELETE_BAN,
            VerdictAction.HARD_BLOCK_FEDBAN,
            VerdictAction.QUARANTINE_CHANNEL_POST,
        }:
            await self.client.queue_delete_message(chat_id, msg_id)

        if result.ban_sender_chat and event.sender_chat_id is not None:
            try:
                await self.client.ban_chat_sender_chat(chat_id, event.sender_chat_id)
            except TelegramAPIError as exc:
                logger.warning("Failed banChatSenderChat(%s, %s): %s", chat_id, event.sender_chat_id, exc)

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

        if result.trigger_lockdown and event.chat_type in {ChatType.GROUP, ChatType.SUPERGROUP}:
            await self._activate_lockdown(chat_id, reason="Automatic anti-raid violation threshold breached")

        if result.alert_owner or result.trigger_lockdown:
            await self._send_owner_alert(event, result)

    # ------------------------------------------------------------------
    # Raid Lockdown & Exact Permission Snapshot/Restore
    # ------------------------------------------------------------------
    async def _activate_lockdown(self, chat_id: int, reason: str) -> None:
        cfg = self.storage.get_chat_config(chat_id)
        try:
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
                f"🚨 <b>EMERGENCY RAID LOCKDOWN ACTIVATED</b>\n"
                f"Chat ID: <code>{chat_id}</code>\n"
                f"Reason: {html.escape(reason)}\n"
                f"Group switched to read-only. Tap below or run <code>/unlock</code> when safe.",
                reply_markup={
                    "inline_keyboard": [
                        [
                            {
                                "text": "🔓 Lift Lockdown & Restore Permissions",
                                "callback_data": self.signer.sign("raid", f"unlock:{chat_id}"),
                                "style": "success",
                            }
                        ]
                    ]
                },
            )
        except TelegramAPIError as exc:
            logger.warning("Failed to activate lockdown in chat %s: %s", chat_id, exc)

    async def _lift_lockdown(self, chat_id: int) -> bool:
        cfg = self.storage.get_chat_config(chat_id)
        restored = (
            json.loads(cfg.saved_permissions_json)
            if cfg.saved_permissions_json
            else RESTORED_USER_PERMISSIONS
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
    # Emoji-Matrix Join Request Gate & Membership Watchdog
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

        if self.storage.get_federation_ban(user_id, cfg.federation_id):
            await self.client.decline_chat_join_request(chat_id, user_id)
            return
        if raid_state == RaidState.LOCKDOWN:
            await self.client.decline_chat_join_request(chat_id, user_id)
            return

        if self.config.reputation.cas_enabled:
            is_cas = await self.engine.reputation._check_cas(user_id)
            if is_cas:
                await self.client.decline_chat_join_request(chat_id, user_id)
                return

        if cfg.require_join_verification or raid_state == RaidState.ELEVATED:
            user_chat_id = int(req.get("user_chat_id") or user_id)
            cap_text, cap_markup, _ = build_emoji_captcha(
                chat_id=chat_id,
                chat_title=str(chat.get("title", "this community")),
                user_id=user_id,
                signer=self.signer,
            )
            try:
                sent = await self.client.send_message(
                    chat_id=user_chat_id, text=cap_text, reply_markup=cap_markup
                )
                self._schedule_captcha_timeout(
                    chat_id, user_id, user_chat_id, sent.get("message_id") if isinstance(sent, dict) else None
                )
            except TelegramAPIError:
                pass
        else:
            await self.client.approve_chat_join_request(chat_id, user_id)

    def _schedule_captcha_timeout(
        self, chat_id: int, user_id: int, dm_chat_id: int, prompt_msg_id: int | None, timeout_s: float = 90.0
    ) -> None:
        key = (chat_id, user_id)
        old = self._pending_captchas.pop(key, None)
        if old:
            old.cancel()

        async def _expire() -> None:
            try:
                await asyncio.sleep(timeout_s)
                await self.client.decline_chat_join_request(chat_id, user_id)
                if prompt_msg_id:
                    await self.client.queue_delete_message(dm_chat_id, prompt_msg_id)
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            finally:
                self._pending_captchas.pop(key, None)

        self._pending_captchas[key] = asyncio.create_task(_expire())

    # ------------------------------------------------------------------
    # Signed Interactive Callback Router (Zero Forgery + Server-Side Admin Auth!)
    # ------------------------------------------------------------------
    async def _handle_callback_query(self, cb: dict[str, Any]) -> None:
        raw_data = str(cb.get("data") or "")
        from_user = cb.get("from") or {}
        caller_id = int(from_user["id"])
        cb_id = str(cb["id"])
        cb_msg = cb.get("message") or {}
        cb_chat_id = int((cb_msg.get("chat") or {}).get("id", 0))
        cb_msg_id = cb_msg.get("message_id")

        verified = self.signer.verify(raw_data, ttl_seconds=86400 * 7)
        if verified is None:
            await self.client.answer_callback_query(
                cb_id, "Expired or invalid security token. Please re-open the menu.", show_alert=True
            )
            return

        action, payload = verified

        # 1. Emoji-Matrix Captcha Verification (`cap:<chat_id>:<user_id>:<1|0>`)
        if action == "cap":
            parts = payload.split(":")
            if len(parts) != 3:
                await self.client.answer_callback_query(cb_id, "Malformed challenge.", show_alert=True)
                return
            target_chat, expected_uid, is_correct = int(parts[0]), int(parts[1]), parts[2] == "1"
            if caller_id != expected_uid:
                await self.client.answer_callback_query(cb_id, "This challenge belongs to another user.", show_alert=True)
                return

            timer = self._pending_captchas.pop((target_chat, expected_uid), None)
            if timer:
                timer.cancel()

            if is_correct:
                try:
                    await self.client.approve_chat_join_request(target_chat, expected_uid)
                    await self.client.answer_callback_query(cb_id, "✅ Verified! Welcome aboard.")
                    if cb_chat_id and cb_msg_id:
                        await self.client.edit_message_text(
                            cb_chat_id, cb_msg_id, "✅ <b>Verification Passed!</b> Your join request has been approved."
                        )
                except TelegramAPIError:
                    await self.client.answer_callback_query(cb_id, "Request already handled.", show_alert=True)
            else:
                try:
                    await self.client.decline_chat_join_request(target_chat, expected_uid)
                except TelegramAPIError:
                    pass
                await self.client.answer_callback_query(cb_id, "❌ Wrong emoji. Request declined.", show_alert=True)
                if cb_chat_id and cb_msg_id:
                    await self.client.edit_message_text(
                        cb_chat_id, cb_msg_id, "❌ <b>Verification Failed.</b> Please re-request joining if you are human."
                    )
            return

        # 2. Onboarding Home Buttons (`home:<chats|picker|privacy>`)
        if action == "home":
            if payload == "picker":
                await self.client.answer_callback_query(cb_id)
                await self.client.send_message(
                    cb_chat_id,
                    "🔗 <b>Native Chat &amp; Channel Picker</b>\nTap a button below to bind your Group, Channel, or Owner Alert Chat:",
                    reply_markup=render_native_chat_picker_keyboard(),
                )
            elif payload == "privacy":
                await self.client.answer_callback_query(cb_id)
                await self.client.send_message(
                    cb_chat_id,
                    f"🔒 <b>AegisTG Privacy Policy (ToS Sec 4 Compliant)</b>\n"
                    f"• Transient in-memory content inspection only.\n"
                    f"• Zero data scraping or AI/ML model training.\n"
                    f"• Edit-bait hashes auto-expire after {self.config.edit_bait.snapshot_ttl_days} days.\n"
                    f"• Full Policy: {html.escape(self.config.privacy_policy_url)}\n"
                    f"• Developer: <a href=\"{__developer_telegram__}\">{__developer__}</a> • "
                    f"<a href=\"{__developer_website__}\">drkingbd.cc</a>",
                )
            elif payload == "chats":
                chats = self.storage.list_chat_configs(enabled_only=True)
                await self.client.answer_callback_query(cb_id)
                if not chats:
                    await self.client.send_message(
                        cb_chat_id,
                        "No protected groups or channels registered yet! Add AegisTG as Admin or tap <b>Native Chat Picker</b>.",
                    )
                else:
                    cfg = chats[0]
                    await self._render_panel_in_place(cb_chat_id, cb_msg_id, cfg.chat_id, tab="overview")
            return

        # All remaining actions are privileged — verify admin authorization on the target chat!
        if action == "tab":
            tab, cid_str = payload.split(":", 1)
            target_chat = int(cid_str)
            if not await self._can_manage_chat(target_chat, caller_id):
                await self.client.answer_callback_query(cb_id, "Admin permission required.", show_alert=True)
                return
            await self.client.answer_callback_query(cb_id)
            await self._render_panel_in_place(cb_chat_id, cb_msg_id, target_chat, tab=tab)
            return

        if action == "tog":
            setting, cid_str = payload.split(":", 1)
            target_chat = int(cid_str)
            if not await self._can_manage_chat(target_chat, caller_id):
                await self.client.answer_callback_query(cb_id, "Admin permission required.", show_alert=True)
                return
            cfg = self.storage.get_chat_config(target_chat)
            if setting == "strict":
                cfg.strict_channel_guard = not cfg.strict_channel_guard
                note = f"Strict Channel Guard: {'ON' if cfg.strict_channel_guard else 'OFF'}"
            else:
                cfg.require_join_verification = not cfg.require_join_verification
                note = f"Emoji Join Gate: {'ON' if cfg.require_join_verification else 'OFF'}"
            self.storage.upsert_chat_config(cfg)
            await self.client.answer_callback_query(cb_id, f"✅ {note}")
            await self._render_panel_in_place(cb_chat_id, cb_msg_id, target_chat, tab="overview")
            return

        if action == "raid":
            mode, cid_str = payload.split(":", 1)
            target_chat = int(cid_str)
            if not await self._can_manage_chat(target_chat, caller_id):
                await self.client.answer_callback_query(cb_id, "Admin permission required.", show_alert=True)
                return
            if mode == "lock":
                await self._activate_lockdown(target_chat, reason=f"Admin {caller_id} panel lockdown")
                await self.client.answer_callback_query(cb_id, "🚨 Emergency Lockdown ACTIVATED!")
            else:
                ok = await self._lift_lockdown(target_chat)
                await self.client.answer_callback_query(
                    cb_id, "🔓 Lockdown lifted & permissions restored!" if ok else "Could not restore permissions."
                )
            await self._render_panel_in_place(cb_chat_id, cb_msg_id, target_chat, tab="overview")
            return

        if action == "audit":
            target_chat = int(payload)
            if not await self._can_manage_chat(target_chat, caller_id):
                await self.client.answer_callback_query(cb_id, "Admin permission required.", show_alert=True)
                return
            await self.client.answer_callback_query(cb_id, "🔍 Running live Security Audit...")
            try:
                info = await self.client.get_chat(target_chat)
                admins = await self.client.get_chat_administrators(target_chat)
                cfg = self.storage.get_chat_config(target_chat)
                report = self.auditor.audit_chat_metadata(info, admins, self.bot_user_id, cfg)
                text, markup = render_audit_card(report, self.signer)
                if cb_chat_id and cb_msg_id:
                    await self.client.edit_message_text(cb_chat_id, cb_msg_id, text, reply_markup=markup)
            except TelegramAPIError as exc:
                await self.client.answer_callback_query(cb_id, f"Audit failed: {exc.description[:80]}", show_alert=True)
            return

        # 3. Self-Healing Owner Triage Callbacks (`tri:ok|fp|fb:...`)
        if action == "tri":
            parts = payload.split(":")
            kind = parts[0]
            inc_id = parts[1]
            target_chat = int(parts[2])
            if not await self._can_manage_chat(target_chat, caller_id):
                await self.client.answer_callback_query(cb_id, "Admin permission required.", show_alert=True)
                return

            if kind == "ok":
                self.storage.record_incident_feedback(inc_id, target_chat, "CONFIRMED", caller_id)
                await self.client.answer_callback_query(cb_id, "✅ Threat confirmed in precision ledger.")
                if cb_chat_id and cb_msg_id:
                    await self.client.edit_message_text(
                        cb_chat_id,
                        cb_msg_id,
                        f"✅ <b>Incident <code>#{inc_id}</code> Confirmed as True Threat</b> by admin <code>{caller_id}</code>.",
                    )
            elif kind == "fp" and len(parts) >= 4:
                actor_id = int(parts[3])
                await self._heal_false_positive(inc_id, target_chat, actor_id, caller_id)
                await self.client.answer_callback_query(cb_id, "↩️ False Positive healed! User unbanned & trust restored.")
                if cb_chat_id and cb_msg_id:
                    await self.client.edit_message_text(
                        cb_chat_id,
                        cb_msg_id,
                        f"↩️ <b>Incident <code>#{inc_id}</code> Marked False Positive</b>\n"
                        f"• User <code>{actor_id}</code> unbanned &amp; trust score boosted\n"
                        f"• Federation ban removed (if applied)\n"
                        f"• Precision telemetry updated by admin <code>{caller_id}</code>",
                    )
            elif kind == "fb" and len(parts) >= 4:
                actor_id = int(parts[3])
                cfg = self.storage.get_chat_config(target_chat)
                self.storage.add_federation_ban(
                    entity_id=actor_id,
                    reason=f"Admin escalated incident #{inc_id}",
                    category="REPUTATION_FEDBAN",
                    source_chat_id=target_chat,
                    federation_id=cfg.federation_id,
                )
                self.storage.record_incident_feedback(inc_id, target_chat, "CONFIRMED", caller_id, notes="fedban")
                await self.client.answer_callback_query(cb_id, "🌐 Entity Federation-Banned across network!")
                if cb_chat_id and cb_msg_id:
                    await self.client.edit_message_text(
                        cb_chat_id,
                        cb_msg_id,
                        f"🌐 <b>Incident <code>#{inc_id}</code> Escalated to Federation Ban</b>\n"
                        f"Actor <code>{actor_id}</code> is now blocked across all linked groups &amp; channels.",
                    )
            return

        await self.client.answer_callback_query(cb_id)

    async def _heal_false_positive(
        self, incident_id: str, chat_id: int, actor_id: int, reviewer_id: int
    ) -> None:
        """Self-healing loop: undo ban/mute/FedBan, boost user trust & record FP precision metric."""
        cfg = self.storage.get_chat_config(chat_id)
        self.storage.record_incident_feedback(incident_id, chat_id, "FALSE_POSITIVE", reviewer_id)
        if actor_id:
            self.storage.remove_federation_ban(actor_id, cfg.federation_id)
            self.storage.heal_user_after_false_positive(chat_id, actor_id)
            try:
                await self.client.unban_chat_member(chat_id, actor_id, only_if_banned=True)
            except TelegramAPIError:
                pass
            try:
                await self.client.restrict_chat_member(chat_id, actor_id, RESTORED_USER_PERMISSIONS)
            except TelegramAPIError:
                pass
        self.metrics.false_positives_healed += 1

    async def _render_panel_in_place(
        self, container_chat_id: int, message_id: int | None, target_chat_id: int, tab: str = "overview"
    ) -> None:
        cfg = self.storage.get_chat_config(target_chat_id)
        raid = self.engine.behavioral.get_raid_state(target_chat_id, time.time())
        stats = self.storage.get_chat_stats(target_chat_id, window_seconds=86400)
        prec = self.storage.get_precision_metrics(target_chat_id)
        recent = self.storage.get_incidents(target_chat_id, limit=8) if tab == "threats" else None
        text, markup = render_control_panel(cfg, raid, stats, prec, self.signer, tab=tab, recent_incidents=recent)
        if message_id:
            try:
                await self.client.edit_message_text(container_chat_id, message_id, text, reply_markup=markup)
                return
            except TelegramAPIError:
                pass
        await self.client.send_message(container_chat_id, text, reply_markup=markup)

    # ------------------------------------------------------------------
    # Membership & Admin Change Watchdog
    # ------------------------------------------------------------------
    async def _handle_chat_member(self, update: dict[str, Any]) -> None:
        chat = update.get("chat") or {}
        chat_id = int(chat["id"])
        old_status = (update.get("old_chat_member") or {}).get("status", "")
        new_member = update.get("new_chat_member") or {}
        new_status = new_member.get("status", "")
        target_user = new_member.get("user") or {}
        actor = update.get("from") or {}
        now = float(update.get("date") or time.time())

        if old_status != new_status and (
            old_status in {"administrator", "creator"} or new_status in {"administrator", "creator"}
        ):
            self._admin_cache.pop(chat_id, None)
            await self._notify_alert_chat(
                chat_id,
                f"⚠️ <b>ADMIN ROLE CHANGE DETECTED</b>\n"
                f"• Chat: <b>{html.escape(chat.get('title', str(chat_id)))}</b>\n"
                f"• Target: <code>{target_user.get('id')}</code> (@{target_user.get('username') or 'no_user'})\n"
                f"• Change: <code>{old_status}</code> → <code>{new_status}</code>\n"
                f"• Actor: <code>{actor.get('id')}</code> (@{actor.get('username') or 'no_user'})",
            )

        if old_status in {"left", "kicked"} and new_status in {"member", "restricted"}:
            uid = int(target_user["id"])
            cfg = self.storage.get_chat_config(chat_id)
            if self.storage.get_federation_ban(uid, cfg.federation_id):
                try:
                    await self.client.ban_chat_member(chat_id, uid, revoke_messages=True)
                except TelegramAPIError:
                    pass
                return

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
            card_text, card_markup = render_welcome_card(self.bot_username, self.signer)
            sent = await self.client.send_message(chat_id, card_text, reply_markup=card_markup)
            if chat_type != ChatType.PRIVATE and isinstance(sent, dict) and sent.get("message_id"):
                self.client.schedule_auto_delete(chat_id, int(sent["message_id"]), delay_seconds=30.0)
            return True

        if cmd_token in {"/about", "/dev"}:
            dev_text, dev_markup = render_dev_info_card()
            sent = await self.client.send_message(chat_id, dev_text, reply_markup=dev_markup)
            if chat_type != ChatType.PRIVATE and isinstance(sent, dict) and sent.get("message_id"):
                self.client.schedule_auto_delete(chat_id, int(sent["message_id"]), delay_seconds=30.0)
            return True

        if cmd_token == "/connect" and chat_type == ChatType.PRIVATE:
            await self.client.send_message(
                chat_id,
                "🔗 <b>One-Tap Chat &amp; Channel Binding</b>\n"
                "Choose a Group, Channel, or Owner Alert Chat directly from Telegram's native picker:",
                reply_markup=render_native_chat_picker_keyboard(),
            )
            return True

        if cmd_token == "/privacy":
            sent = await self.client.send_message(
                chat_id,
                f"🔒 <b>AegisTG Privacy Policy</b>\n"
                f"• Message text is inspected transiently in RAM only.\n"
                f"• Zero data scraping or AI/ML model training (strict Telegram ToS compliance).\n"
                f"• Edit-bait hashes auto-expire in {self.config.edit_bait.snapshot_ttl_days} days.\n"
                f"• Full Policy: {html.escape(self.config.privacy_policy_url)}\n"
                f"• Developer: <a href=\"{__developer_telegram__}\">{__developer__}</a> • "
                f"<a href=\"{__developer_website__}\">drkingbd.cc</a>",
            )
            if chat_type != ChatType.PRIVATE and isinstance(sent, dict) and sent.get("message_id"):
                self.client.schedule_auto_delete(chat_id, int(sent["message_id"]), delay_seconds=25.0)
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

        if cmd_token == "/panel":
            target_id = chat_id
            if chat_type == ChatType.PRIVATE:
                registered = self.storage.list_chat_configs(enabled_only=True)
                if not registered:
                    await self.client.send_message(
                        chat_id,
                        "No groups or channels bound yet! Use /connect or add AegisTG as Admin first.",
                    )
                    return True
                target_id = registered[0].chat_id
            await self._render_panel_in_place(chat_id, None, target_id, tab="overview")
            return True

        if cmd_token == "/digest":
            cfg = self.storage.get_chat_config(chat_id)
            stats_7d = self.storage.get_chat_stats(chat_id, window_seconds=7 * 86400)
            prec = self.storage.get_precision_metrics(chat_id)
            d_text, d_markup = render_digest_card(cfg, stats_7d, prec, self.signer)
            await self.client.send_message(chat_id, d_text, reply_markup=d_markup)
            return True

        if cmd_token == "/status":
            cfg = self.storage.get_chat_config(chat_id)
            stats = self.storage.get_chat_stats(chat_id, window_seconds=86400)
            prec = self.storage.get_precision_metrics(chat_id)
            raid = self.engine.behavioral.get_raid_state(chat_id, time.time())
            text_out, markup = render_control_panel(cfg, raid, stats, prec, self.signer, tab="overview")
            await self.client.send_message(chat_id, text_out, reply_markup=markup)
            return True

        if cmd_token == "/audit":
            try:
                await self.client.send_chat_action(chat_id, "typing")
            except TelegramAPIError:
                pass
            try:
                info = await self.client.get_chat(chat_id)
                admins = await self.client.get_chat_administrators(chat_id)
                cfg = self.storage.get_chat_config(chat_id)
                report = self.auditor.audit_chat_metadata(info, admins, self.bot_user_id, cfg)
                a_text, a_markup = render_audit_card(report, self.signer)
                effect = (
                    EFFECT_CELEBRATION
                    if chat_type == ChatType.PRIVATE and report.score >= 95
                    else None
                )
                await self.client.send_message(
                    chat_id, a_text, reply_markup=a_markup, message_effect_id=effect
                )
            except TelegramAPIError as exc:
                await self.client.send_message(chat_id, f"Audit failed: {html.escape(str(exc))}")
            return True

        if cmd_token == "/lockdown":
            await self._activate_lockdown(chat_id, reason="Manual admin /lockdown command")
            sent = await self.client.send_message(
                chat_id, "🚨 <b>Emergency Lockdown ACTIVATED.</b> Group is now read-only."
            )
            if chat_type != ChatType.PRIVATE and isinstance(sent, dict) and sent.get("message_id"):
                self.client.schedule_auto_delete(chat_id, int(sent["message_id"]), delay_seconds=20.0)
            return True

        if cmd_token == "/unlock":
            ok = await self._lift_lockdown(chat_id)
            sent = await self.client.send_message(
                chat_id,
                "🔓 <b>Lockdown lifted</b> and exact pre-lockdown permissions restored."
                if ok
                else "Could not restore permissions — verify bot has Restrict Members permission.",
            )
            if chat_type != ChatType.PRIVATE and isinstance(sent, dict) and sent.get("message_id"):
                self.client.schedule_auto_delete(chat_id, int(sent["message_id"]), delay_seconds=20.0)
            return True

        if cmd_token == "/strict_channel" and args:
            cfg = self.storage.get_chat_config(chat_id)
            cfg.strict_channel_guard = args[0].lower() in {"on", "true", "1", "yes"}
            self.storage.upsert_chat_config(cfg)
            await self.client.send_message(
                chat_id, f"🛡 Strict Channel Auto-Quarantine set to <code>{cfg.strict_channel_guard}</code>."
            )
            return True

        if cmd_token == "/allow_domain" and args:
            domain = args[0].lower().strip()
            cfg = self.storage.get_chat_config(chat_id)
            if domain not in cfg.allowlist_domains:
                cfg.allowlist_domains.append(domain)
                self.storage.upsert_chat_config(cfg)
            await self.client.send_message(chat_id, f"✅ Domain <code>{html.escape(domain)}</code> whitelisted.")
            return True

        if cmd_token == "/set_alert_chat":
            target_id = int(args[0]) if args and args[0].lstrip("-").isdigit() else chat_id
            cfg = self.storage.get_chat_config(chat_id)
            cfg.alert_chat_id = target_id
            self.storage.upsert_chat_config(cfg)
            await self.client.send_message(
                chat_id, f"📡 Owner Security Alert Chat set to <code>{target_id}</code>."
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
                chat_id, f"🌐 Entity <code>{target_uid}</code> added to Federation Ban List."
            )
            return True

        if cmd_token == "/fedunban" and args and args[0].lstrip("-").isdigit():
            target_uid = int(args[0])
            cfg = self.storage.get_chat_config(chat_id)
            removed = self.storage.remove_federation_ban(target_uid, cfg.federation_id)
            await self.client.send_message(
                chat_id,
                f"✅ Entity <code>{target_uid}</code> removed from Federation Ban List."
                if removed
                else f"Entity <code>{target_uid}</code> was not Federation-banned.",
            )
            return True

        if cmd_token == "/ban_media" and msg.get("reply_to_message"):
            media = await self._parse_media(msg["reply_to_message"])
            if media and media.raw_bytes:
                try:
                    dhash = compute_dhash(media.raw_bytes)
                except DecompressionBombDetected:
                    dhash = None
                if dhash is not None:
                    reason = " ".join(args) or "Admin-banned scam/raid visual flyer"
                    self.engine.media_analyzer.index_banned_hash(
                        dhash, "SCAM_PHISHING_SAFEGUARD", reason
                    )
                    await self.client.send_message(
                        chat_id,
                        f"🖼 Perceptual dHash <code>{dhash:016x}</code> permanently banned &amp; indexed in O(log N) BK-Tree!",
                        reply_markup={
                            "inline_keyboard": [
                                [{"text": "📋 Copy dHash", "copy_text": {"text": f"{dhash:016x}"}}]
                            ]
                        },
                    )
                    return True
            await self.client.send_message(chat_id, "Reply to a photo/image message to ban its perceptual hash.")
            return True

        if cmd_token == "/export_audit":
            pack_json = self.auditor.format_appeal_json(chat_id, days=30)
            await self.client.send_message(
                chat_id,
                f"📄 <b>Appeal Forensics Pack (30d)</b>\n"
                f"<blockquote expandable><pre>{html.escape(pack_json[:3400])}</pre></blockquote>",
                reply_markup={
                    "inline_keyboard": [
                        [
                            {
                                "text": "📋 Copy Appeal Email",
                                "copy_text": {"text": "abuse@telegram.org"},
                            }
                        ]
                    ]
                },
            )
            return True

        if cmd_token == "/purge_chat_data":
            self.storage.purge_chat_data(chat_id)
            await self.client.send_message(
                chat_id, "🧹 All stored AegisTG security metadata for this chat has been permanently erased."
            )
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

        # Native emoji reaction feedback on the user's draft message!
        if reply_to:
            rx = "👍" if res.action == VerdictAction.ALLOW else ("👀" if res.action == VerdictAction.WARN_MONITOR else "⚡")
            try:
                await self.client.set_message_reaction(chat_id, reply_to, rx)
            except TelegramAPIError:
                pass

        card_text, card_markup = render_draft_card(res, draft_preview=draft_text)
        await self.client.send_message(
            chat_id=chat_id,
            reply_to_message_id=reply_to,
            text=card_text,
            reply_markup=card_markup,
        )

    # ------------------------------------------------------------------
    # Authorization & Parsing Helpers
    # ------------------------------------------------------------------
    async def _can_manage_chat(self, target_chat_id: int, user_id: int) -> bool:
        """Server-side admin check (never trust client-side UI visibility alone!)."""
        return await self._is_user_admin(target_chat_id, user_id)

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
        return [
            EntityInfo(
                type=str(e.get("type", "")),
                offset=int(e.get("offset", 0)),
                length=int(e.get("length", 0)),
                url=e.get("url"),
                user_id=(e.get("user") or {}).get("id"),
            )
            for e in raw_entities
        ]

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
        inc_id = result.incident_id or "adhoc"
        card_text, card_markup = render_owner_alert_card(event, result, inc_id, self.signer)
        await self._notify_alert_chat(event.chat_id, card_text, reply_markup=card_markup)

    async def _notify_alert_chat(
        self,
        source_chat_id: int,
        html_text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        cfg = self.storage.get_chat_config(source_chat_id)
        target = cfg.alert_chat_id or self.config.owner_alert_chat_id
        if target is None:
            return
        try:
            await self.client.send_message(target, html_text, reply_markup=reply_markup)
        except TelegramAPIError as exc:
            logger.warning("Failed sending owner alert to %s: %s", target, exc)
