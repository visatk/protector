"""URL, Telegram Entity, Public Suffix List (PSL) & IDNA Homograph Intelligence Analyzer."""

from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import urlparse

import idna
import publicsuffix2

from protector.config import UrlsConfig
from protector.models import ChatConfig, RiskSignal, TelegramEvent, ThreatCategory
from protector.normalizer import HOMOGLYPH_MAP, LEET_MAP, NormalizedText

_RE_URL = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\]\)]+|"
    r"(?<!@)\b(?:t\.me|telegram\.me|telegram\.dog)/[^\s<>\"'\]\)]+",
    re.IGNORECASE,
)
_RE_BARE_DOMAIN = re.compile(
    r"(?<!@)\b[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:xyz|top|click|tk|ml|ga|cf|gq|icu|buzz|vip|cfd|sbs|io|org|com|net)\b(?:/[^\s]*)?",
    re.IGNORECASE,
)

OFFICIAL_BRAND_DOMAINS: dict[str, set[str]] = {
    "telegram": {"telegram.org", "t.me", "telegram.me", "telegram.dog", "telegra.ph", "telesco.pe"},
    "botfather": {"t.me", "telegram.org"},
    "fragment": {"fragment.com"},
    "safeguard": {"safeguard.run"},
    "tonkeeper": {"tonkeeper.com"},
    "binance": {"binance.com", "binance.us"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "bkash": {"bkash.com"},
    "nagad": {"nagad.com.bd"},
}

SUSPICIOUS_PATH_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "auth",
    "session",
    "safeguard",
    "airdrop",
    "claim",
    "wallet",
    "seed",
    "recover",
    "unlock",
    "bonus",
    "gift",
    "nitro",
    "premium-free",
)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _registrable_domain(host: str) -> str:
    """Extract true eTLD+1 via Public Suffix List (e.g., evil.telegram.org.co.uk -> org.co.uk)."""
    host = host.lower().strip(".")
    try:
        sld = publicsuffix2.get_sld(host, strict=False)
        return (sld or host).lower()
    except Exception:
        return host


def _domain_matches(host: str, candidate_domains: set[str]) -> bool:
    host = host.lower().strip(".")
    sld = _registrable_domain(host)
    for d in candidate_domains:
        d = d.lower().strip(".")
        if host == d or host.endswith("." + d) or sld == d:
            # Guard against subdomain spoofing like telegram.org.evil.com!
            if host == d or host.endswith("." + d):
                return True
    return False


def _decode_idna_safe(host: str) -> tuple[str, bool]:
    """Decode punycode (xn--) back to Unicode to expose hidden homoglyph brand spoofing."""
    if "xn--" not in host:
        return host, False
    try:
        decoded = idna.decode(host)
        return decoded.lower(), True
    except Exception:
        return host, True


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def extract_urls(event: TelegramEvent, norm: NormalizedText) -> list[tuple[str, bool]]:
    """Return list of (url, is_hidden_text_link) extracted from entities and text."""
    found: list[tuple[str, bool]] = []
    seen: set[str] = set()

    # 1. Telegram entities (catches hidden markdown/HTML text_link attacks!)
    for ent in event.entities:
        if ent.type == "text_link" and ent.url:
            key = ent.url.strip()
            if key not in seen:
                seen.add(key)
                found.append((key, True))
        elif ent.type == "url" and event.text:
            snippet = event.text[ent.offset : ent.offset + ent.length].strip()
            if snippet and snippet not in seen:
                seen.add(snippet)
                found.append((snippet, False))

    # 2. Regex on cleaned + homoglyph-folded text
    for text_src in (norm.cleaned, norm.folded_ascii):
        for match in _RE_URL.finditer(text_src):
            raw = match.group(0).rstrip(".,;:!?)")
            if raw not in seen:
                seen.add(raw)
                found.append((raw, False))

    # 3. Bare suspicious domains without http://
    if not found:
        for match in _RE_BARE_DOMAIN.finditer(norm.folded_ascii):
            raw = match.group(0).rstrip(".,;:!?)")
            if raw not in seen:
                seen.add(raw)
                found.append((raw, False))

    return found


class UrlIntelAnalyzer:
    """Evaluates URLs & entities using Public Suffix List, IDNA decoding, and brand-spoof detection."""

    def __init__(self, config: UrlsConfig) -> None:
        self.config = config
        self._allowlist = {d.lower() for d in config.allowlist_domains}
        self._denylist = {d.lower() for d in config.denylist_domains}
        self._shorteners = {d.lower() for d in config.shortener_domains}
        self._high_risk_tlds = tuple(t.lower() for t in config.high_risk_tlds)
        self._brands = [b.lower() for b in config.protected_brands]

    def analyze(
        self,
        event: TelegramEvent,
        norm: NormalizedText,
        chat_cfg: ChatConfig,
    ) -> tuple[list[RiskSignal], int, int]:
        """Return (signals, total_url_count, untrusted_url_count)."""
        urls = extract_urls(event, norm)
        if not urls:
            return [], 0, 0

        chat_allowlist = self._allowlist | {d.lower() for d in chat_cfg.allowlist_domains}
        signals: list[RiskSignal] = []
        untrusted_count = 0

        for raw_url, is_hidden_text_link in urls:
            normalized_url = raw_url if "://" in raw_url else f"https://{raw_url}"
            try:
                parsed = urlparse(normalized_url)
            except ValueError:
                continue

            host = (parsed.hostname or "").lower().strip(".")
            path_query = f"{parsed.path}?{parsed.query}".lower()
            if not host:
                continue

            # 1. Explicit Denylist (Instant High Severity)
            if _domain_matches(host, self._denylist):
                untrusted_count += 1
                signals.append(
                    RiskSignal(
                        layer="url_intel",
                        category=ThreatCategory.SCAM_PHISHING_SAFEGUARD,
                        score=92,
                        reason=f"Known malicious/phishing domain blocked: {host}",
                        hard_block=True,
                        evidence={"host": host, "hidden_link": is_hidden_text_link},
                    )
                )
                continue

            # 2. Telegram Invite Link Hijacking (t.me/+..., t.me/joinchat/...)
            if host in {"t.me", "telegram.me", "telegram.dog"}:
                if (
                    self.config.block_external_telegram_invites_for_non_admins
                    and not event.is_admin
                    and (
                        parsed.path.startswith("/+")
                        or parsed.path.lower().startswith("/joinchat/")
                        or "startapp=" in path_query
                    )
                ):
                    untrusted_count += 1
                    signals.append(
                        RiskSignal(
                            layer="url_intel",
                            category=ThreatCategory.SPAM_SHILL_FLOOD,
                            score=65 if not is_hidden_text_link else 78,
                            reason=f"Unauthorized external Telegram invite/mini-app link ({raw_url[:48]})",
                            evidence={"host": host, "path": parsed.path[:32]},
                        )
                    )
                continue

            # 3. Allowlisted Safe Domains (PSL-verified so telegram.org.evil.co.uk is NOT allowlisted!)
            if _domain_matches(host, chat_allowlist):
                continue

            untrusted_count += 1
            url_risk = 0
            reasons: list[str] = []

            # 4. IDN / Punycode Homograph Attack (decodes xn-- back to Unicode!)
            decoded_host, is_punycode = _decode_idna_safe(host)
            if is_punycode:
                url_risk += 50
                reasons.append(f"IDN/punycode homograph domain ({decoded_host})")

            # 5. Raw IP-literal URL
            if _is_ip_host(host):
                url_risk += 48
                reasons.append("raw IP address URL")

            # 6. Protected Brand Typosquatting / Impersonation (homoglyph + leetspeak folded!)
            folded_host = decoded_host.translate(HOMOGLYPH_MAP).translate(LEET_MAP)
            host_alnum = re.sub(r"[^a-z0-9]", "", folded_host)
            sld = _registrable_domain(host)
            for brand in self._brands:
                official = OFFICIAL_BRAND_DOMAINS.get(brand, set())
                if brand in host_alnum and not _domain_matches(host, official):
                    url_risk += 68
                    reasons.append(f"brand impersonation/typosquatting ({brand} on {sld})")
                    break

            # 7. URL Shortener (often hides phishing/malware redirects)
            if _domain_matches(host, self._shorteners):
                url_risk += 32 if not event.is_admin else 15
                reasons.append("obfuscated URL shortener")

            # 8. High-Risk TLD
            if any(host.endswith(tld) for tld in self._high_risk_tlds):
                url_risk += 24
                reasons.append("high-risk TLD")

            # 9. Credential-Harvesting Path Keywords
            hit_kw = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_query or kw in host]
            if hit_kw:
                url_risk += min(32, 16 + 8 * len(hit_kw))
                reasons.append(f"phishing path keywords ({','.join(hit_kw[:3])})")

            # 10. Hidden Hyperlink Masking ([Safe Label](https://evil.xyz))
            if is_hidden_text_link and url_risk >= 20:
                url_risk += 18
                reasons.append("masked hidden text_link entity")

            # 11. Executable Download Link in URL path
            if re.search(r"\.(?:apk|exe|msi|scr|ps1|bat|sh|dmg|iso)(?:$|\?)", path_query):
                url_risk += 65
                reasons.append("direct executable/APK download URL")

            # 12. High Entropy Random Subdomain (DGA / disposable phishing host)
            leftmost = host.split(".")[0]
            if len(leftmost) >= 14 and _shannon_entropy(leftmost) >= 3.7:
                url_risk += 18
                reasons.append("high-entropy disposable subdomain")

            if url_risk >= 25:
                capped = min(95, url_risk)
                signals.append(
                    RiskSignal(
                        layer="url_intel",
                        category=(
                            ThreatCategory.MALWARE_EXPLOIT
                            if "executable/APK" in " ".join(reasons)
                            else ThreatCategory.SCAM_PHISHING_SAFEGUARD
                        ),
                        score=capped,
                        reason=f"Suspicious URL '{host}': {', '.join(reasons)}",
                        hard_block=capped >= 90,
                        evidence={
                            "host": host,
                            "registrable_domain": sld,
                            "reasons": reasons,
                            "hidden_link": is_hidden_text_link,
                        },
                    )
                )

        return signals, len(urls), untrusted_count
