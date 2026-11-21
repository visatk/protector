"""Media, Malware Payload & 64-bit Perceptual Image Hash (dHash) Guard."""

from __future__ import annotations

import io
import zipfile
from collections import defaultdict, deque
from pathlib import PurePosixPath

from PIL import Image

from protector.config import MediaConfig
from protector.models import RiskSignal, TelegramEvent, ThreatCategory
from protector.normalizer import BIDI_OVERRIDE_CHARS
from protector.storage import Storage

MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "Windows PE Executable (EXE/DLL/SCR)"),
    (b"\x7fELF", "Linux ELF Binary"),
    (b"\xca\xfe\xba\xbe", "Java/Mach-O Binary"),
    (b"#!/", "Executable Shell Script"),
)


def compute_dhash(image_bytes: bytes, hash_size: int = 8) -> int | None:
    """Compute a 64-bit gradient difference perceptual hash (dHash) via Pillow.

    Resilient to resizing, JPEG recompression, minor color shifts, and subtle borders.
    """
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            gray = img.convert("L").resize(
                (hash_size + 1, hash_size), Image.Resampling.LANCZOS
            )
            pixels = list(gray.getdata())
    except Exception:
        return None

    diff_hash = 0
    for row in range(hash_size):
        row_start = row * (hash_size + 1)
        for col in range(hash_size):
            diff_hash <<= 1
            if pixels[row_start + col] > pixels[row_start + col + 1]:
                diff_hash |= 1
    return diff_hash


def hamming_distance(h1: int, h2: int) -> int:
    """Bit-level Hamming distance between two 64-bit perceptual hashes."""
    return (h1 ^ h2).bit_count()


def _detect_apk_in_zip(raw: bytes) -> bool:
    """Detect Android APK disguised as a ZIP/document via AndroidManifest.xml."""
    if not raw.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = set(zf.namelist()[:64])
            return "AndroidManifest.xml" in names or "classes.dex" in names
    except Exception:
        return False


class MediaGuardAnalyzer:
    """Inspects files, executables, MIME mismatches, and visual scam flyers (dHash)."""

    def __init__(self, config: MediaConfig, storage: Storage) -> None:
        self.config = config
        self.storage = storage
        self._dangerous_exts = {ext.lower() for ext in config.dangerous_extensions}
        # In-memory sliding window tracking viral identical image waves: dhash -> deque[(ts, user_id)]
        self._recent_media_waves: dict[int, deque[tuple[float, int]]] = defaultdict(deque)

    def analyze(self, event: TelegramEvent) -> list[RiskSignal]:
        media = event.media
        if media is None:
            return []

        signals: list[RiskSignal] = []

        # 1. Filename Inspection (RTL override spoofing, dangerous extensions, double extensions)
        if media.file_name:
            fname = media.file_name
            if any(ch in BIDI_OVERRIDE_CHARS for ch in fname):
                signals.append(
                    RiskSignal(
                        layer="media_guard",
                        category=ThreatCategory.MALWARE_EXPLOIT,
                        score=95,
                        reason="RTL-override spoofed filename (classic malware disguise)",
                        hard_block=True,
                        evidence={"file_name": repr(fname)},
                    )
                )

            clean_name = "".join(ch for ch in fname if ch not in BIDI_OVERRIDE_CHARS).strip().lower()
            suffixes = [s.lower() for s in PurePosixPath(clean_name).suffixes]

            if suffixes:
                final_ext = suffixes[-1]
                if final_ext in self._dangerous_exts:
                    is_double = len(suffixes) >= 2 and suffixes[-2] in {
                        ".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx", ".xls", ".txt", ".mp4"
                    }
                    score = 94 if is_double else 82
                    signals.append(
                        RiskSignal(
                            layer="media_guard",
                            category=ThreatCategory.MALWARE_EXPLOIT,
                            score=score,
                            reason=(
                                f"Disguised double-extension malware file ({''.join(suffixes[-2:])})"
                                if is_double
                                else f"High-risk executable/installer attachment ({final_ext})"
                            ),
                            hard_block=is_double or final_ext in {".apk", ".exe", ".scr", ".ps1", ".hta", ".lnk"},
                            evidence={"file_name": clean_name, "ext": final_ext, "double_ext": is_double},
                        )
                    )

        # 2. MIME-Type Check for Executables / Android Packages
        if media.mime_type:
            mime = media.mime_type.lower()
            if mime in {
                "application/vnd.android.package-archive",
                "application/x-msdownload",
                "application/x-msdos-program",
                "application/x-dosexec",
                "application/x-sh",
                "application/x-bat",
                "application/x-executable",
            }:
                signals.append(
                    RiskSignal(
                        layer="media_guard",
                        category=ThreatCategory.MALWARE_EXPLOIT,
                        score=88,
                        reason=f"Blocked dangerous executable MIME type: {mime}",
                        hard_block=True,
                        evidence={"mime_type": mime},
                    )
                )

        # 3. Magic-Byte Payload Inspection (catches spoofed .pdf/.jpg executables & APKs)
        if media.raw_bytes:
            head = media.raw_bytes[:16]
            for sig, label in MAGIC_SIGNATURES:
                if head.startswith(sig):
                    signals.append(
                        RiskSignal(
                            layer="media_guard",
                            category=ThreatCategory.MALWARE_EXPLOIT,
                            score=94,
                            reason=f"Binary magic-byte mismatch detected: {label}",
                            hard_block=True,
                            evidence={"detected_binary": label},
                        )
                    )
                    break

            if _detect_apk_in_zip(media.raw_bytes):
                signals.append(
                    RiskSignal(
                        layer="media_guard",
                        category=ThreatCategory.MALWARE_EXPLOIT,
                        score=94,
                        reason="Hidden Android APK payload inside uploaded archive/file",
                        hard_block=True,
                        evidence={"detected_binary": "Android APK"},
                    )
                )

            # 4. 64-bit Perceptual Image Hash (dHash) Matching & Viral Wave Detection
            if media.media_type in {"photo", "sticker", "document"}:
                dhash = compute_dhash(media.raw_bytes)
                if dhash is not None:
                    signals.extend(self._check_perceptual_hash(event, dhash))

        return signals

    def _check_perceptual_hash(self, event: TelegramEvent, dhash: int) -> list[RiskSignal]:
        signals: list[RiskSignal] = []

        # 4a. Match against known banned scam/raid/NSFW flyer hash DB
        banned_hashes = self.storage.list_banned_media_hashes()
        for known_hash, cat_str, reason in banned_hashes:
            dist = hamming_distance(dhash, known_hash)
            if dist <= self.config.dhash_hamming_threshold:
                try:
                    category = ThreatCategory(cat_str)
                except ValueError:
                    category = ThreatCategory.SCAM_PHISHING_SAFEGUARD
                signals.append(
                    RiskSignal(
                        layer="media_guard",
                        category=category,
                        score=92,
                        reason=f"Perceptual hash match to banned media (Hamming distance={dist}): {reason}",
                        hard_block=True,
                        evidence={"dhash": f"{dhash:016x}", "hamming_distance": dist},
                    )
                )
                return signals

        # 4b. Zero-day Viral Raid Flyer Detection (same image sent by >= N distinct users in window)
        if event.user_id is not None and not event.is_admin:
            now = event.timestamp
            window = self.config.viral_media_window_seconds

            # Find existing near-identical bucket (Hamming <= 6)
            matched_bucket: int | None = None
            for existing_hash in list(self._recent_media_waves.keys()):
                dq = self._recent_media_waves[existing_hash]
                while dq and now - dq[0][0] > window:
                    dq.popleft()
                if not dq:
                    del self._recent_media_waves[existing_hash]
                    continue
                if hamming_distance(dhash, existing_hash) <= 6:
                    matched_bucket = existing_hash
                    break

            bucket_key = matched_bucket if matched_bucket is not None else dhash
            dq = self._recent_media_waves[bucket_key]
            dq.append((now, event.user_id))
            unique_senders = {uid for _, uid in dq}

            if len(unique_senders) >= self.config.viral_media_unique_users:
                signals.append(
                    RiskSignal(
                        layer="media_guard",
                        category=ThreatCategory.RAID_ANOMALY,
                        score=78,
                        reason=(
                            f"Coordinated viral scam/raid flyer detected "
                            f"({len(unique_senders)} distinct users posted identical image in {window}s)"
                        ),
                        evidence={"dhash": f"{dhash:016x}", "unique_senders": len(unique_senders)},
                    )
                )

        return signals
