"""Media, Malware Payload, Decompression-Bomb Shield & BK-Tree O(log N) 64-bit Perceptual Hash Guard."""

from __future__ import annotations

import io
import zipfile
from collections import OrderedDict, deque
from pathlib import PurePosixPath
from typing import Any

from PIL import Image, ImageOps

from protector.config import MediaConfig
from protector.models import RiskSignal, TelegramEvent, ThreatCategory
from protector.normalizer import BIDI_OVERRIDE_CHARS
from protector.storage import Storage

# Hard cap Pillow decompression at 25 megapixels to neutralize PNG/WebP pixel-bomb OOM DoS
Image.MAX_IMAGE_PIXELS = 25_000_000
MAX_VIRAL_WAVE_BUCKETS = 2000

MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "Windows PE Executable (EXE/DLL/SCR)"),
    (b"\x7fELF", "Linux ELF Binary"),
    (b"\xca\xfe\xba\xbe", "Java/Mach-O Binary"),
    (b"#!/", "Executable Shell Script"),
)


class DecompressionBombDetected(RuntimeError):
    """Raised when an uploaded image attempts a Pillow decompression bomb DoS."""


def compute_dhash(image_bytes: bytes, hash_size: int = 8) -> int | None:
    """Compute a 64-bit gradient difference perceptual hash (dHash) via Pillow.

    - Guards against DecompressionBombError (raises DecompressionBombDetected).
    - Normalizes smartphone EXIF orientation via ImageOps.exif_transpose.
    - Resilient to resizing, JPEG recompression, minor color shifts, and subtle borders.
    """
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            # Verify dimensions before decoding full pixel buffer
            width, height = img.size
            if width * height > Image.MAX_IMAGE_PIXELS:
                raise DecompressionBombDetected(
                    f"Image dimensions {width}x{height} exceed safe pixel cap"
                )
            transposed = ImageOps.exif_transpose(img)
            gray = transposed.convert("L").resize(
                (hash_size + 1, hash_size), Image.Resampling.LANCZOS
            )
            pixels = list(gray.getdata())
    except DecompressionBombDetected:
        raise
    except Image.DecompressionBombError as exc:
        raise DecompressionBombDetected(str(exc)) from exc
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


class _BKNode:
    __slots__ = ("dhash", "category", "reason", "children")

    def __init__(self, dhash: int, category: str, reason: str) -> None:
        self.dhash = dhash
        self.category = category
        self.reason = reason
        self.children: dict[int, _BKNode] = {}


class PerceptualHashBKTree:
    """Burkhard-Keller Metric Tree for O(log N) 64-bit Hamming-distance lookups."""

    def __init__(self) -> None:
        self._root: _BKNode | None = None
        self._count: int = 0

    def __len__(self) -> int:
        return self._count

    def add(self, dhash: int, category: str, reason: str) -> None:
        if self._root is None:
            self._root = _BKNode(dhash, category, reason)
            self._count = 1
            return

        curr = self._root
        while True:
            dist = hamming_distance(curr.dhash, dhash)
            if dist == 0:
                curr.category = category
                curr.reason = reason
                return
            nxt = curr.children.get(dist)
            if nxt is None:
                curr.children[dist] = _BKNode(dhash, category, reason)
                self._count += 1
                return
            curr = nxt

    def query(self, dhash: int, max_distance: int) -> list[tuple[int, str, str, int]]:
        """Return list of (matched_dhash, category, reason, hamming_dist) within max_distance."""
        if self._root is None:
            return []

        matches: list[tuple[int, str, str, int]] = []
        stack = [self._root]
        while stack:
            node = stack.pop()
            dist = hamming_distance(node.dhash, dhash)
            if dist <= max_distance:
                matches.append((node.dhash, node.category, node.reason, dist))
            low = dist - max_distance
            high = dist + max_distance
            for edge_dist, child in node.children.items():
                if low <= edge_dist <= high:
                    stack.append(child)
        matches.sort(key=lambda item: item[3])
        return matches


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
    """Inspects files, executables, pixel bombs, MIME mismatches & visual scam flyers (BK-Tree dHash)."""

    def __init__(self, config: MediaConfig, storage: Storage) -> None:
        self.config = config
        self.storage = storage
        self._dangerous_exts = {ext.lower() for ext in config.dangerous_extensions}
        # Bounded LRU sliding window tracking viral identical image waves: dhash -> deque[(ts, user_id)]
        self._recent_media_waves: OrderedDict[int, deque[tuple[float, int]]] = OrderedDict()
        # O(log N) in-memory BK-Tree synchronized with SQLite banned_media_hashes
        self._bk_tree = PerceptualHashBKTree()
        self._known_db_count = -1
        self.reload_hash_index()

    def reload_hash_index(self) -> int:
        """Rebuild in-memory BK-Tree from SQLite banned_media_hashes."""
        tree = PerceptualHashBKTree()
        rows = self.storage.list_banned_media_hashes()
        for h_int, cat, reason in rows:
            tree.add(h_int, cat, reason)
        self._bk_tree = tree
        self._known_db_count = len(rows)
        return self._known_db_count

    def index_banned_hash(self, dhash: int, category: str, reason: str) -> None:
        """Add a newly banned perceptual hash directly into both SQLite and live BK-Tree."""
        self.storage.add_banned_media_hash(dhash, category, reason)
        self._bk_tree.add(dhash, category, reason)
        self._known_db_count = len(self._bk_tree)

    def _sync_if_needed(self) -> None:
        # Lightweight sync check in case hashes were added directly via Storage
        rows = self.storage.list_banned_media_hashes()
        if len(rows) != self._known_db_count:
            tree = PerceptualHashBKTree()
            for h_int, cat, reason in rows:
                tree.add(h_int, cat, reason)
            self._bk_tree = tree
            self._known_db_count = len(rows)

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

        # 3. Magic-Byte Payload Inspection & Safe Perceptual Hashing
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

            if media.media_type in {"photo", "sticker", "document"}:
                try:
                    dhash = compute_dhash(media.raw_bytes)
                except DecompressionBombDetected as exc:
                    signals.append(
                        RiskSignal(
                            layer="media_guard",
                            category=ThreatCategory.MALWARE_EXPLOIT,
                            score=95,
                            reason=f"Malicious image decompression bomb blocked ({exc})",
                            hard_block=True,
                            evidence={"attack": "decompression_bomb"},
                        )
                    )
                    return signals

                if dhash is not None:
                    signals.extend(self._check_perceptual_hash(event, dhash))

        return signals

    def _check_perceptual_hash(self, event: TelegramEvent, dhash: int) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        self._sync_if_needed()

        # 4a. O(log N) BK-Tree lookup against known banned scam/raid/NSFW flyer hashes
        matches = self._bk_tree.query(dhash, self.config.dhash_hamming_threshold)
        if matches:
            _, cat_str, reason, dist = matches[0]
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

        # 4b. Zero-day Viral Raid Flyer Detection (Bounded LRU memory)
        if event.user_id is not None and not event.is_admin:
            now = event.timestamp
            window = self.config.viral_media_window_seconds

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
            if bucket_key not in self._recent_media_waves:
                if len(self._recent_media_waves) >= MAX_VIRAL_WAVE_BUCKETS:
                    self._recent_media_waves.popitem(last=False)
                self._recent_media_waves[bucket_key] = deque()
            else:
                self._recent_media_waves.move_to_end(bucket_key)

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
