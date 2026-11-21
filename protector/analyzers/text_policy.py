"""8-Category Telegram Terms-of-Service Text Policy Engine (Multilingual EN + BN)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from protector.models import ChatType, EventType, RiskSignal, TelegramEvent, ThreatCategory
from protector.normalizer import NormalizedText


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    category: ThreatCategory
    pattern: re.Pattern[str]
    score: int
    reason: str
    hard_block: bool = False
    match_original: bool = False  # True for Bengali/non-ASCII rules


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.UNICODE)


# Carefully engineered high-precision patterns to avoid false positives on normal discussions
POLICY_RULES: tuple[PolicyRule, ...] = (
    # ------------------------------------------------------------------
    # 1. CSAM / Child Exploitation (Zero Tolerance - Hard Block 100)
    # ------------------------------------------------------------------
    PolicyRule(
        rule_id="csam_explicit_trade",
        category=ThreatCategory.CSAM_EXPLOITATION,
        pattern=_compile(
            r"\b(?:cp\s*(?:links?|mega|pack|folder|vip|group|channel)|"
            r"child\s*(?:porn|abuse\s*video|exploitation\s*pack)|"
            r"underage\s*(?:nudes?|leaks?|mega\s*pack|vip\s*videos?)|"
            r"teen\s*mega\s*cp|pedo\s*(?:pack|link|group))\b"
        ),
        score=100,
        reason="Zero-tolerance CSAM / child exploitation distribution indicator",
        hard_block=True,
    ),
    # ------------------------------------------------------------------
    # 2. Violence / Terrorism / Extremist Incitement (Hard Block 95)
    # ------------------------------------------------------------------
    PolicyRule(
        rule_id="violence_incitement",
        category=ThreatCategory.VIOLENCE_TERRORISM,
        pattern=_compile(
            r"\b(?:how\s+to\s+make\s+(?:a\s+)?(?:bomb|explosive|ied|ricin|molotov)|"
            r"bomb\s*making\s*(?:guide|manual|tutorial)|"
            r"donate\s+to\s+(?:isis|isil|al[\s-]?qaeda|terror\s*cell)|"
            r"(?:mass\s+shooting|beheading\s+video|gore\s+pack\s+vip)|"
            r"kill\s+all\s+(?:jews|muslims|christians|hindus|infidels))\b"
        ),
        score=95,
        reason="Terrorism, explosive synthesis, or explicit violence incitement",
        hard_block=True,
    ),
    # ------------------------------------------------------------------
    # 3. Illegal Goods & Cybercrime (Carding / Drugs / Weapons / Forged IDs)
    # ------------------------------------------------------------------
    PolicyRule(
        rule_id="cybercrime_carding",
        category=ThreatCategory.ILLEGAL_GOODS_CYBERCRIME,
        pattern=_compile(
            r"\b(?:cvv\s*(?:shop|dumps?|fresh|valid)|"
            r"fullz\s*(?:with\s*ssn|for\s*sale|shop|fresh)|"
            r"cloned\s*cards?\s*(?:for\s*sale|shipping|available)|"
            r"bank\s*logs?\s*(?:fresh|for\s*sale|cashout)|"
            r"otp\s*bypass\s*bot|sms\s*bomber\s*vip|carding\s*(?:method|tutorial|group))\b"
        ),
        score=90,
        reason="Cybercrime / carding / stolen financial credentials trade",
        hard_block=True,
    ),
    PolicyRule(
        rule_id="illegal_goods_trade",
        category=ThreatCategory.ILLEGAL_GOODS_CYBERCRIME,
        pattern=_compile(
            r"\b(?:(?:buy|sell|order|plug|menu)\s+(?:cocaine|heroin|meth|fentanyl|mdma|weed\s+delivery|yaba|ইয়াবা)|"
            r"unregistered\s+(?:glock|firearm|pistol|gun)\s+for\s+sale|"
            r"fake\s+(?:passport|nid|national\s+id|driving\s+license|ssn)\s+(?:for\s+sale|service|maker)|"
            r"counterfeit\s+(?:bills|notes|usd|euro|taka)\s+(?:for\s+sale|buy))\b"
        ),
        score=88,
        reason="Illegal goods trafficking (drugs, firearms, counterfeit currency, forged documents)",
        hard_block=True,
    ),
    PolicyRule(
        rule_id="illegal_goods_bn",
        category=ThreatCategory.ILLEGAL_GOODS_CYBERCRIME,
        pattern=_compile(
            r"(?:ইয়াবা|ফেনসিডিল|হিরোইন|অবৈধ\s*অস্ত্র|জাল\s*টাকা|ভুয়া\s*এনআইডি|ফেক\s*পাসপোর্ট)\s*"
            r"(?:বিক্রি|কিনতে|পাওয়া\s*যায়|অর্ডার|সাপ্লাই|ইনবক্স)"
        ),
        score=88,
        reason="Illegal goods / contraband solicitation (Bengali)",
        hard_block=True,
        match_original=True,
    ),
    # ------------------------------------------------------------------
    # 4. Scam, Phishing & Fake Safeguard Verification Attacks
    # ------------------------------------------------------------------
    PolicyRule(
        rule_id="fake_safeguard_rce",
        category=ThreatCategory.SCAM_PHISHING_SAFEGUARD,
        pattern=_compile(
            r"(?:press\s+win\s*\+\s*r|windows\s*\+\s*r|paste\s+(?:into|in)\s+(?:powershell|terminal|cmd|run\s+box)|"
            r"(?:powershell|mshta|curl|wget)\s+[^\n]{0,80}(?:iex|invoke-expression|\|\s*(?:sh|bash))|"
            r"manual\s+verification\s+failed[^\n]{0,60}(?:copy|paste|terminal|powershell))"
        ),
        score=95,
        reason="Fake Safeguard / ClickFix clipboard-malware execution scam",
        hard_block=True,
    ),
    PolicyRule(
        rule_id="telegram_credential_phish",
        category=ThreatCategory.SCAM_PHISHING_SAFEGUARD,
        pattern=_compile(
            r"(?:(?:your\s+)?telegram\s+account\s+(?:will\s+be\s+|is\s+scheduled\s+to\s+be\s+)?(?:banned|deleted|suspended|frozen)\s+(?:in\s+\d+|within)|"
            r"verify\s+your\s+(?:telegram\s+)?(?:account|session|phone\s+number)\s+(?:immediately|now|here)|"
            r"send\s+(?:your\s+)?(?:login\s+code|otp\s+code|2fa\s+password|seed\s+phrase|recovery\s+phrase|private\s+key)|"
            r"connect\s+(?:your\s+)?wallet\s+to\s+claim\s+(?:free\s+)?(?:airdrop|ton|usdt|reward))"
        ),
        score=82,
        reason="Telegram account phishing, seed-phrase theft, or wallet-drainer lure",
    ),
    PolicyRule(
        rule_id="crypto_double_scam",
        category=ThreatCategory.SCAM_PHISHING_SAFEGUARD,
        pattern=_compile(
            r"(?:(?:send|invest|deposit)\s+\$?\d+[^\n]{0,50}(?:get|receive|earn|return)\s+\$?\d+\s*(?:in\s+\d+\s*(?:min|hour)|guaranteed|profit)|"
            r"100%\s*(?:guaranteed|risk[\s-]?free)\s*(?:profit|roi|daily\s*income|trading\s*signal)|"
            r"double\s+your\s+(?:btc|eth|usdt|ton|crypto|money)\s+(?:instantly|today|in\s+\d+)|"
            r"dm\s+(?:me|admin)\s+for\s+(?:guaranteed\s+)?(?:investment|cash\s*flip|money\s*flip))"
        ),
        score=76,
        reason="Fraudulent guaranteed-return / crypto doubling scam pitch",
    ),
    PolicyRule(
        rule_id="scam_bengali_mfs",
        category=ThreatCategory.SCAM_PHISHING_SAFEGUARD,
        pattern=_compile(
            r"(?:(?:বিকাশ|নগদ|রকেট|bkash|nagad)\s*(?:পিন|pin|ওটিপি|otp|কোড)\s*(?:দিন|দাও|পাঠান|শেয়ার)|"
            r"(?:বিনিয়োগ|ইনভেস্ট|ডিপোজিট)\s*করে\s*(?:দ্বিগুণ|ডাবল|১০০%\s*নিশ্চিত|প্রতিদিন\s*\d+\s*টাকা\s*আয়)|"
            r"ফ্রি\s*(?:টাকা|বোনাস|ডলার)\s*(?:নিতে|পেতে)\s*(?:লিংকে\s*ক্লিক|একাউন্ট\s*ভেরিফাই|পিন\s*দিন)|"
            r"টেলিগ্রাম\s*(?:একাউন্ট|চ্যানেল)\s*(?:ব্যান|ডিলিট)\s*হয়ে\s*যাবে[^\n]{0,40}ভেরিফাই)"
        ),
        score=84,
        reason="Bengali MFS (bKash/Nagad) credential phishing or guaranteed-return scam",
        match_original=True,
    ),
    # ------------------------------------------------------------------
    # 5. Doxing & PII Leak Protection
    # ------------------------------------------------------------------
    PolicyRule(
        rule_id="doxing_intent",
        category=ThreatCategory.DOXING_PII_LEAK,
        pattern=_compile(
            r"\b(?:dox(?:ed|xed|ing|xing)?\s+(?:info|pack|drop)|"
            r"home\s+address\s*[:\-]\s*.{5,40}(?:phone|ssn|nid)|"
            r"leaked\s+(?:nid|ssn|aadhaar|passport|private\s+photos?)\s+(?:of|dump))\b"
        ),
        score=80,
        reason="Doxing or non-consensual private personal data exposure",
    ),
    # ------------------------------------------------------------------
    # 6. Copyright / DMCA Takedown Risk (High Priority for Public Channels!)
    # ------------------------------------------------------------------
    PolicyRule(
        rule_id="dmca_piracy_signals",
        category=ThreatCategory.COPYRIGHT_DMCA_RISK,
        pattern=_compile(
            r"\b(?:(?:download|watch|full)\s+(?:(?:hd|full\s*hd|camrip|hdrip|webrip|bluray|4k|1080p|720p)\s+){1,3}(?:free\s+)?(?:movie|movies|web\s*series|episode|episodes)|"
            r"(?:cracked|patched|nulled)\s+(?:apk|software|adobe|windows|course|app|pro\s+version)(?:\s+[a-z0-9+._-]+){0,4}\s+(?:download|link|free|below|here)|"
            r"(?:paid\s+course|udemy|onlyfans|patreon)\s+(?:leaked|mega\s+link|free\s+download|dump)|"
            r"keygen\s*\+\s*crack|torrent\s+magnet\s+download)\b"
        ),
        score=58,
        reason="High DMCA / copyright infringement risk (triggers dmca@telegram.org bans)",
    ),
    # ------------------------------------------------------------------
    # 7. Malware / Spyware / Stealer Distribution
    # ------------------------------------------------------------------
    PolicyRule(
        rule_id="malware_distribution",
        category=ThreatCategory.MALWARE_EXPLOIT,
        pattern=_compile(
            r"\b(?:(?:crypter|fud\s+rat|android\s+rat|stealer\s+logs?|redline\s+stealer|lumma\s+stealer|"
            r"keylogger\s+apk|spyware\s+apk|hack\s+anyone(?:'s)?\s+(?:whatsapp|telegram|facebook)\s+(?:apk|tool)))\b"
        ),
        score=88,
        reason="Malware, spyware, RAT, or infostealer distribution",
        hard_block=True,
    ),
    # ------------------------------------------------------------------
    # 8. Unsolicited Spam / Mass Shilling
    # ------------------------------------------------------------------
    PolicyRule(
        rule_id="spam_shill_promo",
        category=ThreatCategory.SPAM_SHILL_FLOOD,
        pattern=_compile(
            r"(?:join\s+(?:our|my)\s+(?:vip|signal|pump|betting|casino|18\+)\s+(?:channel|group)\s+(?:now|fast|today)|"
            r"(?:buy|cheap)\s+(?:telegram\s+)?(?:fake\s+members?|subscribers?|views?|mass\s+report\s+service)|"
            r"work\s+from\s+home\s+earn\s+\$?\d{3,5}\s*(?:daily|per\s+day|weekly)\s*(?:no\s+experience|dm\s+me))"
        ),
        score=62,
        reason="Unsolicited commercial spam, fake-member service, or mass-shill promo",
    ),
)

_RE_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_RE_BULK_PHONE = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?\(?\d{3,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}")


def _luhn_valid(digits: str) -> bool:
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    # Exclude obviously synthetic strings like 0000000000000000
    if len(set(digits)) <= 2:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class TextPolicyAnalyzer:
    """Evaluates normalized & original text against Telegram ToS categories."""

    def analyze(self, event: TelegramEvent, norm: NormalizedText) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        if not norm.original.strip():
            return signals

        # 1. Obfuscation evasion signal (zero-width, BiDi RTL, mixed Cyrillic/Latin homoglyphs)
        obf_score = norm.obfuscation_score
        if obf_score >= 15:
            details = []
            if norm.bidi_override_count:
                details.append(f"bidi_override={norm.bidi_override_count}")
            if norm.invisible_count >= 3:
                details.append(f"invisible_chars={norm.invisible_count}")
            if norm.mixed_script_tokens:
                details.append(f"homoglyph_tokens={norm.mixed_script_tokens}")
            if norm.spaced_evasion_count:
                details.append(f"spaced_evasion={norm.spaced_evasion_count}")
            signals.append(
                RiskSignal(
                    layer="text_normalizer",
                    category=ThreatCategory.OBFUSCATION_EVASION,
                    score=obf_score,
                    reason=f"Anti-filter Unicode obfuscation detected ({', '.join(details)})",
                    evidence={
                        "bidi": norm.bidi_override_count,
                        "invisible": norm.invisible_count,
                        "mixed_script": norm.mixed_script_tokens,
                    },
                )
            )

        # 2. Policy rule evaluation against folded_ascii, deobfuscated, and original (for Bengali)
        matched_rules: set[str] = set()
        for rule in POLICY_RULES:
            targets = [norm.cleaned] if rule.match_original else [norm.folded_ascii, norm.deobfuscated]
            for candidate in targets:
                if candidate and rule.pattern.search(candidate):
                    if rule.rule_id not in matched_rules:
                        matched_rules.add(rule.rule_id)
                        rule_score = rule.score
                        # Copyright/DMCA risks are substantially more fatal on PUBLIC broadcast channels!
                        if (
                            rule.category == ThreatCategory.COPYRIGHT_DMCA_RISK
                            and event.chat_type == ChatType.CHANNEL
                        ):
                            rule_score = min(85, rule_score + 18)
                        signals.append(
                            RiskSignal(
                                layer="text_policy",
                                category=rule.category,
                                score=rule_score,
                                reason=rule.reason,
                                hard_block=rule.hard_block,
                                evidence={"rule_id": rule.rule_id},
                            )
                        )
                    break

        # 3. Real Luhn credit-card leak / carding dump detector
        luhn_hits = 0
        for m in _RE_CARD_CANDIDATE.finditer(norm.cleaned):
            digits = re.sub(r"[ -]", "", m.group(0))
            if _luhn_valid(digits):
                luhn_hits += 1
        if luhn_hits >= 1:
            signals.append(
                RiskSignal(
                    layer="text_policy",
                    category=ThreatCategory.DOXING_PII_LEAK,
                    score=78 if luhn_hits == 1 else 92,
                    reason=f"Payment card number leak / carding payload detected ({luhn_hits} Luhn-valid sequence(s))",
                    hard_block=luhn_hits >= 2,
                    evidence={"luhn_cards": luhn_hits},
                )
            )

        # 4. Bulk phone-number dump (doxing / lead-scraping dump)
        phones = _RE_BULK_PHONE.findall(norm.cleaned)
        if len(phones) >= 5 and event.event_type != EventType.DRAFT_CHECK:
            signals.append(
                RiskSignal(
                    layer="text_policy",
                    category=ThreatCategory.DOXING_PII_LEAK,
                    score=62,
                    reason=f"Bulk phone number dump detected ({len(phones)} numbers — doxing/spam risk)",
                    evidence={"phone_count": len(phones)},
                )
            )

        # 5. Mention flood (mass @username tagging inside a single message)
        mention_count = sum(1 for e in event.entities if e.type in {"mention", "text_mention"})
        if mention_count == 0:
            mention_count = len(re.findall(r"(?<!\w)@[A-Za-z0-9_]{4,32}\b", norm.cleaned))
        if mention_count >= 7 and not event.is_admin:
            signals.append(
                RiskSignal(
                    layer="text_policy",
                    category=ThreatCategory.SPAM_SHILL_FLOOD,
                    score=52,
                    reason=f"Mass user mention flood ({mention_count} mentions in one message)",
                    evidence={"mention_count": mention_count},
                )
            )

        return signals
