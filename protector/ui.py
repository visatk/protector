"""Telegram Bot Native UI/UX Design System for AegisTG v2.0.

Crafts delightful, scannable, first-party-feeling Telegram experiences using:
- Styled InlineKeyboardButtons (`primary` blue, `success` green, `danger` red)
- Expandable `<blockquote expandable>` forensic & checklist sections
- `CopyTextButton` (`copy_text`) for 1-tap copying of Incident IDs & Appeal Summaries
- `KeyboardButtonRequestChat` native Group/Channel picker for frictionless onboarding
- Randomized Emoji-Matrix Human Verification Gate (language-independent captcha)
- Edit-in-Place Control Center Dashboard (`/panel`) with live progress bars
- Inline Security Scanner cards (`@BotName <url or draft>`)
"""

from __future__ import annotations

import html
import secrets
from typing import Any

from protector.models import AuditReport, ChatConfig, EvaluationResult, IncidentRecord, RaidState, TelegramEvent, VerdictAction
from protector.security import CallbackSigner

# Native Telegram animated message effects (used subtly on DM celebration milestones)
EFFECT_CELEBRATION = "5046509860389126442"  # Party popper / confetti
EFFECT_THUMBS_UP = "5107584321108051014"

# Language-independent Emoji Captcha Pool: (code, emoji, bilingual_label)
CAPTCHA_EMOJIS: tuple[tuple[str, str, str], ...] = (
    ("fox", "🦊", "Fox / শিয়াল"),
    ("owl", "🦉", "Owl / পেঁচা"),
    ("rocket", "🚀", "Rocket / রকেট"),
    ("shield", "🛡", "Shield / ঢাল"),
    ("star", "⭐", "Star / তারা"),
    ("tree", "🌲", "Tree / গাছ"),
    ("crown", "👑", "Crown / মুকুট"),
    ("gem", "💎", "Gem / হীরা"),
    ("anchor", "⚓", "Anchor / নোঙ্গর"),
    ("key", "🔑", "Key / চাবি"),
)

CATEGORY_BADGES: dict[str, str] = {
    "CSAM_EXPLOITATION": "🚨 Zero-Tolerance CSAM",
    "VIOLENCE_TERRORISM": "🚨 Violence / Extremism",
    "ILLEGAL_GOODS_CYBERCRIME": "⛔ Illegal Goods / Cybercrime",
    "SCAM_PHISHING_SAFEGUARD": "🎣 Scam / Phishing / Safeguard",
    "DOXING_PII_LEAK": "🔒 PII / Doxing Leak",
    "COPYRIGHT_DMCA_RISK": "©️ DMCA / Copyright Risk",
    "MALWARE_EXPLOIT": "☣️ Malware / Exploit Payload",
    "SPAM_SHILL_FLOOD": "📢 Spam / Flood",
    "RAID_ANOMALY": "⚔️ Coordinated Raid",
    "EDIT_BAIT_SABOTAGE": "🕵️ Delayed Edit-Bait Sabotage",
    "IMPERSONATION_SPOOFING": "🎭 Channel Spoofing",
    "ADMIN_COMPROMISE": "⚠️ Admin Hijack Anomaly",
    "REPUTATION_FEDBAN": "🌐 Federation Threat Match",
    "OBFUSCATION_EVASION": "🧩 Unicode Obfuscation Evasion",
}


def progress_bar(value: int, total: int = 100, width: int = 10) -> str:
    """Render a crisp visual Unicode progress bar (e.g., █████████░)."""
    ratio = max(0.0, min(1.0, value / max(1, total)))
    filled = int(round(ratio * width))
    return "█" * filled + "░" * (width - filled)


def grade_badge(grade: str) -> str:
    mapping = {
        "A+": "🏆 Fortress Shield (A+)",
        "A": "🛡 Hardened (A)",
        "B": "✅ Good Posture (B)",
        "C": "⚠️ Needs Hardening (C)",
        "D": "🟠 At Risk (D)",
        "F": "🔴 Critical Exposure (F)",
    }
    return mapping.get(grade, grade)


def raid_badge(state: RaidState | str) -> str:
    val = state.value if isinstance(state, RaidState) else str(state)
    return {
        "NORMAL": "🟢 NORMAL",
        "ELEVATED": "🟡 ELEVATED",
        "LOCKDOWN": "🔴 LOCKDOWN",
    }.get(val, val)


def btn(
    text: str,
    *,
    callback_data: str | None = None,
    url: str | None = None,
    copy_text: str | None = None,
    switch_inline_query_current_chat: str | None = None,
    style: str | None = None,  # "primary" | "success" | "danger"
) -> dict[str, Any]:
    """Construct a spec-compliant Bot API 9.x/10.x InlineKeyboardButton."""
    obj: dict[str, Any] = {"text": text}
    if callback_data is not None:
        obj["callback_data"] = callback_data
    if url is not None:
        obj["url"] = url
    if copy_text is not None:
        obj["copy_text"] = {"text": copy_text[:256]}
    if switch_inline_query_current_chat is not None:
        obj["switch_inline_query_current_chat"] = switch_inline_query_current_chat
    if style in {"primary", "success", "danger"}:
        obj["style"] = style
    return obj


# ----------------------------------------------------------------------
# 1. Onboarding Welcome Wizard (/start) & Native Chat Picker (/connect)
# ----------------------------------------------------------------------
def render_welcome_card(bot_username: str, signer: CallbackSigner) -> tuple[str, dict[str, Any]]:
    handle = bot_username or "AegisTGBot"
    text = (
        "🛡 <b>AegisTG — Intelligent Group &amp; Channel Protector</b>\n"
        "<i>9-Layer Defense • Zero-Clutter UX • Telegram ToS Compliant</i>\n\n"
        "Protect your <b>Groups</b>, <b>Linked Comment Groups</b>, and <b>Broadcast Channels</b> "
        "from bans, raids, delayed edit-bait sabotage, phishing, malware, and admin hijacks.\n\n"
        "<blockquote expandable>"
        "<b>How AegisTG Keeps Your Community Safe:</b>\n"
        "• <b>Anti-Raid Shield:</b> Adaptive Lockdown + Emoji Human Verification\n"
        "• <b>Edit-Bait Forensics:</b> Catches hidden delayed edits to old messages\n"
        "• <b>Multilingual Scam &amp; Phishing Guard:</b> EN + বাংলা (bKash/Nagad/Safeguard)\n"
        "• <b>Malware &amp; dHash Media Guard:</b> Stops .apk/.exe &amp; visual scam flyers\n"
        "• <b>Channel Pre-Publish &amp; Hijack Guard:</b> /draft checks + instant auto-quarantine\n"
        "• <b>Self-Healing Precision:</b> 1-tap False Positive undo &amp; learning loop"
        "</blockquote>\n\n"
        "👇 <b>Quick Start:</b> Add AegisTG as Admin (rights pre-filled), or paste any draft post right here to test it before publishing!"
    )
    markup = {
        "inline_keyboard": [
            [
                btn(
                    "➕ Protect a Group",
                    url=f"https://t.me/{handle}?startgroup=setup",
                    style="primary",
                ),
                btn(
                    "📢 Protect a Channel",
                    url=f"https://t.me/{handle}?startchannel=setup",
                    style="primary",
                ),
            ],
            [
                btn(
                    "🔍 Scan a Link Inline",
                    switch_inline_query_current_chat="https://",
                    style="success",
                ),
                btn(
                    "🎛 Control Center",
                    callback_data=signer.sign("home", "chats"),
                ),
            ],
            [
                btn("🔗 Native Chat Picker", callback_data=signer.sign("home", "picker")),
                btn("🔒 Privacy Policy", callback_data=signer.sign("home", "privacy")),
            ],
        ]
    }
    return text, markup


def render_native_chat_picker_keyboard() -> dict[str, Any]:
    """Native Telegram KeyboardButtonRequestChat so users pick chats without numeric IDs."""
    return {
        "keyboard": [
            [
                {
                    "text": "📢 Select My Channel to Bind",
                    "request_chat": {
                        "request_id": 101,
                        "chat_is_channel": True,
                        "bot_is_member": True,
                        "request_title": True,
                    },
                    "style": "primary",
                },
                {
                    "text": "👥 Select My Group to Bind",
                    "request_chat": {
                        "request_id": 102,
                        "chat_is_channel": False,
                        "bot_is_member": True,
                        "request_title": True,
                    },
                    "style": "primary",
                },
            ],
            [
                {
                    "text": "🚨 Pick Private Owner Alert Chat",
                    "request_chat": {
                        "request_id": 103,
                        "chat_is_channel": False,
                        "request_title": True,
                    },
                    "style": "success",
                }
            ],
        ],
        "resize_keyboard": True,
        "one_time_keyboard": True,
    }


# ----------------------------------------------------------------------
# 2. Interactive Edit-in-Place Control Center Dashboard (/panel)
# ----------------------------------------------------------------------
def render_control_panel(
    cfg: ChatConfig,
    raid_state: RaidState,
    stats_24h: dict[str, Any],
    precision: dict[str, Any],
    signer: CallbackSigner,
    tab: str = "overview",
    recent_incidents: list[IncidentRecord] | None = None,
) -> tuple[str, dict[str, Any]]:
    title = html.escape(cfg.title or str(cfg.chat_id))
    cid = cfg.chat_id
    prec_pct = precision.get("precision_pct", 100.0)
    total_inc = stats_24h.get("total_incidents", 0)
    avg_ms = stats_24h.get("avg_latency_ms", 0.0)

    if tab == "threats":
        lines = [
            f"📊 <b>Threat Feed — {title}</b>",
            f"24h Blocked: <b>{total_inc}</b> | Avg Speed: <code>{avg_ms} ms</code>",
            "",
        ]
        if recent_incidents:
            entries = []
            for inc in recent_incidents[:8]:
                badge = CATEGORY_BADGES.get(inc.primary_category, inc.primary_category)
                entries.append(
                    f"• <code>{inc.incident_id}</code> {badge} — <b>{inc.risk_score}/100</b> ({inc.action_taken})"
                )
            lines.append("<blockquote expandable>" + "\n".join(entries) + "</blockquote>")
        else:
            lines.append("✨ <i>Zero threats recorded recently. Your community is spotless!</i>")
        body = "\n".join(lines)

    elif tab == "precision":
        tp = precision.get("confirmed", 0)
        fp = precision.get("false_positives", 0)
        muted_rules = precision.get("muted_rules", [])
        body = (
            f"🧠 <b>Self-Healing Precision — {title}</b>\n"
            f"Accuracy: <code>{progress_bar(int(round(prec_pct)))}</code> <b>{prec_pct:.1f}%</b>\n\n"
            f"• Confirmed Threats: <b>{tp}</b>\n"
            f"• False Positives Healed: <b>{fp}</b>\n"
            f"• Local Soft-Exception Rules: <code>{len(muted_rules)}</code>\n\n"
            "<blockquote expandable>"
            "Whenever an admin taps <b>False Positive &amp; Unban</b> on an alert card, AegisTG "
            "immediately restores the user, lifts any FedBan, boosts their trust score, and adapts "
            "local community precision — with zero AI scraping or external model training."
            "</blockquote>"
        )

    elif tab == "opsec":
        body = (
            f"🔐 <b>Owner OpSec Hardening Guide</b>\n\n"
            "<blockquote expandable>"
            "1. <b>Cold-Vault Ownership:</b> Keep channel/group ownership on a locked-down dedicated account (never your daily browsing account).\n"
            "2. <b>2FA Cloud Password:</b> Enable for owner + all admins (&gt;= 7 days) with a hardware/TOTP-protected recovery email.\n"
            "3. <b>SIM / Port-Out PIN:</b> Lock your mobile carrier against SIM-swap hijacks.\n"
            "4. <b>12-Month Self-Destruct:</b> Set Account Self-Destruct to 12 months so ownership never gets orphaned.\n"
            "5. <b>Linked Comment Parity:</b> Always run AegisTG in BOTH your broadcast channel AND its linked discussion group.\n"
            "6. <b>Zero-Trust Safeguard Rule:</b> Never run PowerShell/Terminal scripts from any verification bot."
            "</blockquote>"
        )

    else:  # overview
        shield_str = "🟢 ACTIVE" if cfg.enabled else "⚪ PAUSED"
        strict_str = "ON" if cfg.strict_channel_guard else "OFF"
        gate_str = "ON" if cfg.require_join_verification else "OFF"
        alert_str = f"<code>{cfg.alert_chat_id}</code>" if cfg.alert_chat_id else "<i>Not set</i>"
        body = (
            f"🎛 <b>AegisTG Control Center</b>\n"
            f"Chat: <b>{title}</b> (<code>{cfg.chat_type}</code>)\n\n"
            f"• Shield Status: <b>{shield_str}</b>\n"
            f"• Raid State: <b>{raid_badge(raid_state)}</b>\n"
            f"• Strict Channel Auto-Quarantine: <code>{strict_str}</code>\n"
            f"• Emoji Join Verification Gate: <code>{gate_str}</code>\n"
            f"• Owner Alert Channel: {alert_str}\n\n"
            f"⚡ <b>24h Telemetry:</b> <b>{total_inc}</b> blocked | "
            f"<code>{avg_ms} ms</code> avg | Precision: <b>{prec_pct:.1f}%</b>"
        )

    is_locked = raid_state == RaidState.LOCKDOWN
    markup = {
        "inline_keyboard": [
            [
                btn(
                    "🛡 Strict Guard: ON" if cfg.strict_channel_guard else "🛡 Strict Guard: OFF",
                    callback_data=signer.sign("tog", f"strict:{cid}"),
                    style="success" if cfg.strict_channel_guard else None,
                ),
                btn(
                    "🧩 Join Gate: ON" if cfg.require_join_verification else "🧩 Join Gate: OFF",
                    callback_data=signer.sign("tog", f"gate:{cid}"),
                    style="success" if cfg.require_join_verification else None,
                ),
            ],
            [
                btn(
                    "🔓 Lift Lockdown" if is_locked else "🚨 Emergency Lockdown",
                    callback_data=signer.sign("raid", f"{'unlock' if is_locked else 'lock'}:{cid}"),
                    style="success" if is_locked else "danger",
                ),
                btn(
                    "🔍 Live Audit",
                    callback_data=signer.sign("audit", f"{cid}"),
                    style="primary",
                ),
            ],
            [
                btn("🏠 Overview", callback_data=signer.sign("tab", f"overview:{cid}")),
                btn("📊 Threats", callback_data=signer.sign("tab", f"threats:{cid}")),
                btn("🧠 Precision", callback_data=signer.sign("tab", f"precision:{cid}")),
                btn("🔐 OpSec", callback_data=signer.sign("tab", f"opsec:{cid}")),
            ],
        ]
    }
    return body, markup


# ----------------------------------------------------------------------
# 3. Interactive Owner Alert Triage Card (with 1-Tap Self-Healing Undo!)
# ----------------------------------------------------------------------
def render_owner_alert_card(
    event: TelegramEvent,
    result: EvaluationResult,
    incident_id: str,
    signer: CallbackSigner,
) -> tuple[str, dict[str, Any]]:
    cat_key = result.primary_category.value if result.primary_category else "POLICY_RISK"
    cat_label = CATEGORY_BADGES.get(cat_key, cat_key)
    actor_id = event.sender_chat_id if result.ban_sender_chat else (event.user_id or 0)
    actor_kind = "channel" if result.ban_sender_chat else "user"

    evidence_lines = [
        f"• [{s.layer} • +{s.score}] {html.escape(s.reason)}"
        for s in sorted(result.signals, key=lambda x: -x.score)[:5]
    ]
    evidence_block = "\n".join(evidence_lines) or "• Heuristic policy threshold triggered"

    text = (
        f"🚨 <b>AegisTG Security Incident</b>  <code>#{incident_id}</code>\n"
        f"<b>{cat_label}</b>\n\n"
        f"• Risk: <code>{progress_bar(result.risk_score)}</code> <b>{result.risk_score}/100</b>\n"
        f"• Action: <code>{result.action.value}</code> ({result.latency_ms:.1f} ms)\n"
        f"• Chat: <code>{event.chat_id}</code> ({event.chat_type.value} • {event.event_type.value})\n"
        f"• Actor ({actor_kind}): <code>{actor_id}</code>\n\n"
        f"<blockquote expandable><b>Detection Evidence:</b>\n{evidence_block}</blockquote>"
    )

    rows: list[list[dict[str, Any]]] = [
        [
            btn(
                "✅ Confirm Threat",
                callback_data=signer.sign("tri", f"ok:{incident_id}:{event.chat_id}"),
                style="success",
            ),
            btn(
                "↩️ False Positive & Unban",
                callback_data=signer.sign("tri", f"fp:{incident_id}:{event.chat_id}:{actor_id}"),
                style="primary",
            ),
        ],
        [
            btn(
                "🌐 FedBan Network",
                callback_data=signer.sign("tri", f"fb:{incident_id}:{event.chat_id}:{actor_id}"),
                style="danger",
            ),
            btn(
                "📋 Copy ID",
                copy_text=incident_id,
            ),
        ],
    ]
    return text, {"inline_keyboard": rows}


# ----------------------------------------------------------------------
# 4. Emoji-Matrix Human Verification Challenge
# ----------------------------------------------------------------------
def build_emoji_captcha(
    chat_id: int, chat_title: str, user_id: int, signer: CallbackSigner
) -> tuple[str, dict[str, Any], str]:
    """Generate a randomized 6-emoji human challenge with HMAC-signed callback buttons.

    Returns (html_text, reply_markup, target_code).
    """
    pool = list(CAPTCHA_EMOJIS)
    # Fisher-Yates secure sample of 6 emojis
    chosen: list[tuple[str, str, str]] = []
    for _ in range(6):
        idx = secrets.randbelow(len(pool))
        chosen.append(pool.pop(idx))

    target_code, target_emoji, target_label = chosen[secrets.randbelow(len(chosen))]
    safe_title = html.escape(chat_title or "this community")

    text = (
        f"🛡 <b>Human Verification Required</b>\n"
        f"Welcome to <b>{safe_title}</b>!\n\n"
        f"To block automated raid bots, please tap the <b>{target_label}</b> button below within <b>90 seconds</b>:"
    )

    # 2 rows x 3 emoji buttons
    row1 = []
    row2 = []
    for i, (code, emoji, _) in enumerate(chosen):
        ok_flag = "1" if code == target_code else "0"
        button = btn(
            f"{emoji}",
            callback_data=signer.sign("cap", f"{chat_id}:{user_id}:{ok_flag}"),
        )
        (row1 if i < 3 else row2).append(button)

    return text, {"inline_keyboard": [row1, row2]}, target_code


# ----------------------------------------------------------------------
# 5. Enhanced Audit Scorecard & Draft Scan Cards
# ----------------------------------------------------------------------
def render_audit_card(report: AuditReport, signer: CallbackSigner) -> tuple[str, dict[str, Any]]:
    icons = {"PASS": "✅", "INFO": "ℹ️", "WARNING": "⚠️", "CRITICAL": "🔴"}
    findings_lines = [
        f"{icons.get(f.severity, '•')} <b>{html.escape(f.title)}</b> ({f.points_earned}/{f.points_possible})\n"
        f"   ↳ {html.escape(f.recommendation)}"
        for f in report.findings
    ]
    opsec_lines = [f"{i}. {html.escape(item)}" for i, item in enumerate(report.opsec_checklist, 1)]

    text = (
        f"🛡 <b>AegisTG Security Posture Audit</b>\n"
        f"Chat: <b>{html.escape(report.title)}</b> (<code>{report.chat_type}</code>)\n\n"
        f"Score: <code>{progress_bar(report.score)}</code> <b>{report.score}/100</b>\n"
        f"Status: <b>{grade_badge(report.grade)}</b>\n\n"
        f"<blockquote expandable><b>Security Controls Breakdown:</b>\n"
        + "\n".join(findings_lines)
        + "</blockquote>\n"
        + "<blockquote expandable><b>Owner OpSec Essentials:</b>\n"
        + "\n".join(opsec_lines)
        + "</blockquote>"
    )
    markup = {
        "inline_keyboard": [
            [
                btn("🔄 Re-run Audit", callback_data=signer.sign("audit", f"{report.chat_id}"), style="primary"),
                btn("🎛 Open Panel", callback_data=signer.sign("tab", f"overview:{report.chat_id}")),
            ]
        ]
    }
    return text, markup


def render_draft_card(result: EvaluationResult, draft_preview: str = "") -> tuple[str, dict[str, Any] | None]:
    if result.action == VerdictAction.ALLOW:
        header = "✅ <b>SAFE TO PUBLISH</b>"
    elif result.action == VerdictAction.WARN_MONITOR:
        header = "⚠️ <b>REVIEW WARNING BEFORE PUBLISHING</b>"
    else:
        header = "🚫 <b>HIGH BAN RISK — DO NOT PUBLISH</b>"

    signals_txt = "\n".join(
        f"• [{s.layer} • +{s.score}] {html.escape(s.reason)}" for s in result.signals
    ) or "• Clean — zero Telegram ToS, phishing, PII, or DMCA risk signals detected."

    text = (
        f"🧪 <b>Pre-Publish Compliance Scan</b>\n"
        f"{header}\n\n"
        f"Risk: <code>{progress_bar(result.risk_score)}</code> <b>{result.risk_score}/100</b> "
        f"(<code>{result.latency_ms:.1f} ms</code>)\n\n"
        f"<blockquote expandable><b>Compliance Details:</b>\n{signals_txt}</blockquote>"
    )
    markup = None
    if result.action == VerdictAction.ALLOW and draft_preview:
        markup = {"inline_keyboard": [[btn("📋 Copy Clean Draft", copy_text=draft_preview, style="success")]]}
    return text, markup


def render_inline_scan_result(query_text: str, result: EvaluationResult) -> list[dict[str, Any]]:
    """Build native InlineQueryResultArticle for `@BotName <url or draft>` instant scanning."""
    if result.action == VerdictAction.ALLOW:
        title = f"✅ SAFE ({result.risk_score}/100) — Ready to Share"
        desc = "No Telegram ToS, phishing, malware, or DMCA risks detected."
    elif result.action == VerdictAction.WARN_MONITOR:
        title = f"⚠️ CAUTION ({result.risk_score}/100) — Potential Policy Risk"
        desc = result.summary[:110]
    else:
        title = f"🚫 DANGEROUS ({result.risk_score}/100) — High Ban/Scam Risk!"
        desc = result.summary[:110]

    msg_html, _ = render_draft_card(result)
    return [
        {
            "type": "article",
            "id": secrets.token_hex(8),
            "title": title,
            "description": desc,
            "input_message_content": {
                "message_text": msg_html,
                "parse_mode": "HTML",
                "link_preview_options": {"is_disabled": True},
            },
        }
    ]


def render_digest_card(
    cfg: ChatConfig,
    stats_7d: dict[str, Any],
    precision: dict[str, Any],
    signer: CallbackSigner,
) -> tuple[str, dict[str, Any]]:
    """Render an engaging 7-Day Community Protection Digest keeping admins informed & coming back."""
    title = html.escape(cfg.title or str(cfg.chat_id))
    total = stats_7d.get("total_incidents", 0)
    avg_ms = stats_7d.get("avg_latency_ms", 0.0)
    prec_pct = precision.get("precision_pct", 100.0)
    by_cat = stats_7d.get("by_category") or {}

    cat_lines = [
        f"• {CATEGORY_BADGES.get(cat, cat)}: <b>{cnt}</b>"
        for cat, cnt in sorted(by_cat.items(), key=lambda kv: -kv[1])[:6]
    ]
    breakdown = "\n".join(cat_lines) or "• Zero malicious attempts in the past 7 days! 🎉"

    text = (
        f"📈 <b>7-Day Protection Digest — {title}</b>\n\n"
        f"🛡 Threats Neutralized: <b>{total}</b>\n"
        f"⚡ Avg Intercept Speed: <code>{avg_ms} ms</code>\n"
        f"🎯 Precision Rate: <code>{progress_bar(int(round(prec_pct)))}</code> <b>{prec_pct:.1f}%</b>\n\n"
        f"<blockquote expandable><b>Blocked Threat Breakdown:</b>\n{breakdown}</blockquote>\n"
        f"<i>Your community stayed compliant with Telegram ToS all week.</i>"
    )
    summary_copy = f"AegisTG 7-Day Digest ({cfg.title}): {total} threats blocked, {avg_ms}ms avg latency, {prec_pct:.1f}% precision."
    markup = {
        "inline_keyboard": [
            [
                btn("🔍 Run Security Audit", callback_data=signer.sign("audit", f"{cfg.chat_id}"), style="primary"),
                btn("📋 Copy Summary", copy_text=summary_copy),
            ]
        ]
    }
    return text, markup
