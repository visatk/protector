"""Group & Channel Security Posture Auditor (/audit) & Forensic Appeal Pack Exporter (/export_audit)."""

from __future__ import annotations

import datetime
import json
from typing import Any

from protector.models import AuditFinding, AuditReport, ChatConfig
from protector.storage import Storage

OPSEC_CHECKLIST: list[str] = [
    "Isolate Ownership: Hold channel/group ownership on a dedicated locked-down 'Cold Vault' account (never your daily browsing account).",
    "Enable Two-Step Verification (Cloud Password) on owner + all admins for >= 7 days with a 2FA-protected recovery email.",
    "Set carrier SIM / Port-Out PIN to prevent SIM-swapping takeover attacks.",
    "Set Account Self-Destruct (Settings > Privacy > Delete if away) to 12 months so ownership is never orphaned.",
    "Audit Active Sessions (Settings > Devices) weekly and terminate unrecognized logins immediately.",
    "Train all admins against Fake Safeguard scams: NEVER run terminal/PowerShell commands or enter OTPs on external sites.",
]


def _score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


class SecurityAuditor:
    """Evaluates live Telegram chat metadata & admin lists to generate a 0-100 Security Health Score."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def audit_chat_metadata(
        self,
        chat_info: dict[str, Any],
        admins: list[dict[str, Any]],
        bot_user_id: int,
        chat_cfg: ChatConfig,
    ) -> AuditReport:
        chat_id = int(chat_info.get("id", chat_cfg.chat_id))
        chat_type = str(chat_info.get("type", chat_cfg.chat_type))
        title = str(chat_info.get("title", chat_cfg.title or str(chat_id)))
        findings: list[AuditFinding] = []

        # 1. Check Bot Administrator Permissions (20 pts)
        bot_admin = next(
            (a for a in admins if (a.get("user") or {}).get("id") == bot_user_id), None
        )
        if not bot_admin:
            findings.append(
                AuditFinding(
                    check_id="bot_admin_rights",
                    title="Protector Bot Admin Permissions",
                    severity="CRITICAL",
                    points_earned=0,
                    points_possible=20,
                    recommendation="Promote AegisTG to Administrator with Delete Messages, Ban/Restrict Users, and Invite Users rights.",
                )
            )
        else:
            required = (
                ["can_delete_messages", "can_post_messages", "can_edit_messages"]
                if chat_type == "channel"
                else ["can_delete_messages", "can_restrict_members", "can_invite_users"]
            )
            missing = [r for r in required if not bot_admin.get(r)]
            if not missing:
                findings.append(
                    AuditFinding(
                        check_id="bot_admin_rights",
                        title="Protector Bot Admin Permissions",
                        severity="PASS",
                        points_earned=20,
                        points_possible=20,
                        recommendation="All required bot protection rights are granted.",
                    )
                )
            else:
                earned = max(5, 20 - 6 * len(missing))
                findings.append(
                    AuditFinding(
                        check_id="bot_admin_rights",
                        title="Protector Bot Admin Permissions",
                        severity="WARNING",
                        points_earned=earned,
                        points_possible=20,
                        recommendation=f"Grant missing rights to AegisTG: {', '.join(missing)}.",
                    )
                )

        # 2. Admin Privilege Sprawl (15 pts)
        human_admins = [a for a in admins if not (a.get("user") or {}).get("is_bot")]
        promoters = [
            a for a in human_admins if a.get("status") != "creator" and a.get("can_promote_members")
        ]
        if len(promoters) == 0 and len(human_admins) <= 5:
            findings.append(
                AuditFinding(
                    check_id="admin_least_privilege",
                    title="Admin Least-Privilege Hygiene",
                    severity="PASS",
                    points_earned=15,
                    points_possible=15,
                    recommendation=f"Clean admin surface ({len(human_admins)} human admins, 0 non-owner promoters).",
                )
            )
        elif len(promoters) > 0:
            findings.append(
                AuditFinding(
                    check_id="admin_least_privilege",
                    title="Admin Least-Privilege Hygiene",
                    severity="WARNING",
                    points_earned=6,
                    points_possible=15,
                    recommendation=(
                        f"{len(promoters)} non-owner admin(s) have 'Add New Admins' permission. "
                        "Revoke 'can_promote_members' to limit blast radius if an admin account is hijacked."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check_id="admin_least_privilege",
                    title="Admin Least-Privilege Hygiene",
                    severity="INFO",
                    points_earned=11,
                    points_possible=15,
                    recommendation=f"{len(human_admins)} human admins detected; periodically remove inactive admins.",
                )
            )

        # 3. Owner Alert Channel Configured (15 pts)
        if chat_cfg.alert_chat_id:
            findings.append(
                AuditFinding(
                    check_id="owner_alert_channel",
                    title="Real-Time Owner Alert Channel",
                    severity="PASS",
                    points_earned=15,
                    points_possible=15,
                    recommendation="Owner security alerts and rogue-admin warnings are routed properly.",
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check_id="owner_alert_channel",
                    title="Real-Time Owner Alert Channel",
                    severity="WARNING",
                    points_earned=0,
                    points_possible=15,
                    recommendation="Configure a private Security Alert Chat (/set_alert_chat) for instant raid & hijack notifications.",
                )
            )

        # 4. Protected Content (10 pts)
        if chat_info.get("has_protected_content"):
            findings.append(
                AuditFinding(
                    check_id="protected_content",
                    title="Restrict Saving Content",
                    severity="PASS",
                    points_earned=10,
                    points_possible=10,
                    recommendation="Content forwarding/saving restrictions are enabled.",
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check_id="protected_content",
                    title="Restrict Saving Content",
                    severity="INFO",
                    points_earned=5,
                    points_possible=10,
                    recommendation="Consider enabling 'Restrict Saving Content' if protecting proprietary media/IP.",
                )
            )

        # 5. Chat-Type Specific Critical Controls (40 pts total)
        if chat_type == "channel":
            # 5a. Linked Discussion Group Protection Parity (25 pts)
            linked_id = chat_info.get("linked_chat_id")
            if linked_id:
                if self.storage.is_chat_registered(int(linked_id)):
                    findings.append(
                        AuditFinding(
                            check_id="linked_group_parity",
                            title="Linked Discussion Group Parity",
                            severity="PASS",
                            points_earned=25,
                            points_possible=25,
                            recommendation="Linked comment group is actively protected by AegisTG.",
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            check_id="linked_group_parity",
                            title="Linked Discussion Group Parity",
                            severity="CRITICAL",
                            points_earned=0,
                            points_possible=25,
                            recommendation=(
                                f"Linked discussion group ({linked_id}) is NOT protected by AegisTG! "
                                "Raiders frequently flood comments with ToS-violating content to trigger collateral channel bans. Add AegisTG as Admin there immediately."
                            ),
                        )
                    )
            else:
                findings.append(
                    AuditFinding(
                        check_id="linked_group_parity",
                        title="Linked Discussion Group Parity",
                        severity="PASS",
                        points_earned=25,
                        points_possible=25,
                        recommendation="No unmoderated linked discussion group attached.",
                    )
                )

            # 5b. Strict Auto-Quarantine for Channel Posts (15 pts)
            if chat_cfg.strict_channel_guard:
                findings.append(
                    AuditFinding(
                        check_id="strict_channel_guard",
                        title="Strict Channel Auto-Quarantine",
                        severity="PASS",
                        points_earned=15,
                        points_possible=15,
                        recommendation="Strict channel guard enabled: critical ToS/hijack posts are auto-quarantined.",
                    )
                )
            else:
                findings.append(
                    AuditFinding(
                        check_id="strict_channel_guard",
                        title="Strict Channel Auto-Quarantine",
                        severity="WARNING",
                        points_earned=6,
                        points_possible=15,
                        recommendation="Enable /strict_channel on to auto-delete hijacked/phishing/CSAM channel posts within milliseconds.",
                    )
                )
        else:
            # Supergroup / Group specific checks (40 pts total)
            # 5a. Native Aggressive Anti-Spam (15 pts)
            if chat_info.get("has_aggressive_anti_spam_enabled"):
                findings.append(
                    AuditFinding(
                        check_id="native_aggressive_antispam",
                        title="Telegram Native Aggressive Anti-Spam",
                        severity="PASS",
                        points_earned=15,
                        points_possible=15,
                        recommendation="Telegram's native Aggressive Anti-Spam filter is active alongside AegisTG.",
                    )
                )
            else:
                findings.append(
                    AuditFinding(
                        check_id="native_aggressive_antispam",
                        title="Telegram Native Aggressive Anti-Spam",
                        severity="WARNING",
                        points_earned=3,
                        points_possible=15,
                        recommendation="Enable Telegram's built-in Aggressive Anti-Spam (Group Info > Administrators > Anti-Spam, available at 200+ members).",
                    )
                )

            # 5b. Slow Mode (10 pts)
            slow = int(chat_info.get("slow_mode_delay") or 0)
            if slow >= 10:
                findings.append(
                    AuditFinding(
                        check_id="slow_mode",
                        title="Slow Mode Flood Damping",
                        severity="PASS",
                        points_earned=10,
                        points_possible=10,
                        recommendation=f"Slow Mode active ({slow}s interval).",
                    )
                )
            else:
                findings.append(
                    AuditFinding(
                        check_id="slow_mode",
                        title="Slow Mode Flood Damping",
                        severity="WARNING",
                        points_earned=2,
                        points_possible=10,
                        recommendation="Enable Slow Mode (10s–30s) in Group Permissions to neutralize raid flooding.",
                    )
                )

            # 5c. Default Member Permissions Hygiene (15 pts)
            perms = chat_info.get("permissions") or {}
            risky_defaults = [
                k
                for k in ("can_add_web_page_previews", "can_invite_users", "can_send_other_messages")
                if perms.get(k) is True
            ]
            if not risky_defaults:
                findings.append(
                    AuditFinding(
                        check_id="default_permissions",
                        title="Default Member Permission Hardening",
                        severity="PASS",
                        points_earned=15,
                        points_possible=15,
                        recommendation="Default member permissions are safely hardened.",
                    )
                )
            else:
                earned = max(3, 15 - 4 * len(risky_defaults))
                findings.append(
                    AuditFinding(
                        check_id="default_permissions",
                        title="Default Member Permission Hardening",
                        severity="WARNING",
                        points_earned=earned,
                        points_possible=15,
                        recommendation=f"Consider restricting default member permissions: {', '.join(risky_defaults)}.",
                    )
                )

        total_earned = sum(f.points_earned for f in findings)
        total_possible = max(1, sum(f.points_possible for f in findings))
        score = int(round((total_earned / total_possible) * 100))

        return AuditReport(
            chat_id=chat_id,
            chat_type=chat_type,
            title=title,
            score=score,
            grade=_score_to_grade(score),
            findings=findings,
            opsec_checklist=OPSEC_CHECKLIST,
        )

    def format_audit_report(self, report: AuditReport) -> str:
        lines = [
            f"<b>AegisTG Security Posture Audit</b>",
            f"Chat: <b>{report.title}</b> (<code>{report.chat_type}</code>)",
            f"Health Score: <b>{report.score}/100 (Grade {report.grade})</b>",
            "",
        ]
        icons = {"PASS": "[OK]", "INFO": "[INFO]", "WARNING": "[WARN]", "CRITICAL": "[CRIT]"}
        for f in report.findings:
            lines.append(
                f"{icons.get(f.severity, '[*]')} <b>{f.title}</b> ({f.points_earned}/{f.points_possible})\n"
                f"   -> {f.recommendation}"
            )
        lines.append("")
        lines.append("<b>Owner OpSec Essentials:</b>")
        for idx, item in enumerate(report.opsec_checklist[:4], 1):
            lines.append(f"{idx}. {item}")
        return "\n".join(lines)

    def build_appeal_forensics_pack(self, chat_id: int, days: int = 30) -> dict[str, Any]:
        """Generate a privacy-redacted compliance proof pack for abuse@telegram.org appeals."""
        since = datetime.datetime.now(datetime.timezone.utc).timestamp() - days * 86400
        cfg = self.storage.get_chat_config(chat_id)
        incidents = self.storage.get_incidents(chat_id, limit=500, since_ts=since)
        stats = self.storage.get_chat_stats(chat_id, window_seconds=days * 86400)

        return {
            "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "purpose": "Proactive Telegram Terms-of-Service Compliance & Moderation Proof (abuse@telegram.org)",
            "chat": {
                "chat_id": cfg.chat_id,
                "chat_type": cfg.chat_type,
                "title": cfg.title,
                "raid_state": cfg.raid_state,
                "strict_channel_guard": cfg.strict_channel_guard,
            },
            "window_days": days,
            "summary_metrics": stats,
            "recent_enforcements_sample": [
                {
                    "incident_id": inc.incident_id,
                    "utc_time": datetime.datetime.fromtimestamp(
                        inc.timestamp, tz=datetime.timezone.utc
                    ).isoformat(),
                    "event_type": inc.event_type,
                    "primary_category": inc.primary_category,
                    "risk_score": inc.risk_score,
                    "action_taken": inc.action_taken,
                    "response_latency_ms": inc.latency_ms,
                }
                for inc in incidents[:25]
            ],
        }

    def format_appeal_json(self, chat_id: int, days: int = 30) -> str:
        return json.dumps(self.build_appeal_forensics_pack(chat_id, days=days), indent=2)
