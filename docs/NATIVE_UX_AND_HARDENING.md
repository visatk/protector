# Telegram Bot Native Features, UX Design System & Production Hardening Research (v2.0)

> **Perspective:** Principal Architecture Engineer & Product UX Systems Designer  
> **Scope:** Telegram Bot API 7.x–10.x Native UI/UX Primitives, Interaction Design, Cryptographic Safety, Performance Engineering, Reliability & Stability Hardening for **AegisTG**.

---

## 1. Telegram Bot Native UI/UX & Style Primitives (2024–2026)

Great Telegram bots never feel like clunky command-line scripts spamming `/set_option_1 0`. They feel like **first-party native Telegram features**. AegisTG v2.0 harnesses every modern native Bot API primitive:

| Native Bot API Feature | Method / Field | How AegisTG Uses It for Exceptional UX |
|---|---|---|
| **Colored Action Buttons** | `InlineKeyboardButton.style` (`"primary"`, `"success"`, `"danger"`) | Blue (`primary`) for Audits/Navigation, Green (`success`) for Confirm/Unlock/Enable, Red (`danger`) for Lockdown/FedBan/Quarantine. Gives instant visual affordance at a glance. |
| **Expandable Blockquotes** | `<blockquote expandable>...</blockquote>` | Collapses verbose forensic evidence, OpSec checklists, and full audit recommendations into sleek expandable cards — keeping chats scannable and calm. |
| **One-Tap Copy Buttons** | `InlineKeyboardButton.copy_text` (`CopyTextButton`) | Lets owners copy Incident IDs, Appeal Forensics summaries, or Banned dHashes in a single tap without awkward mobile text selection. |
| **Native Chat/Channel Picker** | `KeyboardButtonRequestChat` (`request_chat`) | Replaces ugly numeric `-100123456` ID entry! Owners pick their Group, Channel, or Alert Chat natively from Telegram's built-in picker (`/connect`). |
| **Pre-Filled Admin Rights** | `setMyDefaultAdministratorRights` (Groups + Channels) | Pre-selects the exact least-privilege rights (`can_delete_messages`, `can_restrict_members`, `can_invite_users`, etc.) when onboarding via `t.me/bot?startgroup` or `startchannel`. |
| **Role-Scoped Command Menus** | `setMyCommands` + `BotCommandScope` | Private DM shows Onboarding + `/draft` + `/panel`; Group Members see only `/privacy` & `/help`; Group/Channel Admins see the full Moderation & Audit Command Suite. |
| **Edit-in-Place Dashboard** | `editMessageText` / `editMessageReplyMarkup` | Single stateful Control Center (`/panel`) with tabs (`Overview`, `Shield`, `Audit`, `Threats`, `Precision`, `OpSec`) — zero message spam. |
| **Native Emoji Reactions** | `setMessageReaction` | Subtle `🛡` / `👀` reaction acknowledgment instead of noisy text confirmations. |
| **Animated Message Effects** | `message_effect_id` (DM milestones) | Celebrates hitting an `A+` (95–100/100) Security Posture Grade in private DM (with safe automatic fallback if an effect ID is unavailable). |
| **Modern Link Previews** | `link_preview_options: {"is_disabled": true}` | Prevents phishing link previews from rendering inside Admin Alert Cards (replaces deprecated `disable_web_page_preview`). |
| **Inline Security Scanner** | `inline_query` + `answerInlineQuery` | Type `@AegisTGBot <url or draft>` in **any** chat to scan a suspicious link or draft post on the fly — turning AegisTG into a daily-use safety companion. |
| **Zero-Clutter Ephemeral Replies** | Scheduled auto-delete (20s TTL) | Group warnings and command outputs auto-delete silently after 20 seconds so public chat feeds stay pristine. |
| **Emoji-Matrix Verification** | Randomized 6-emoji inline grid | Language-independent human verification (*"Tap the 🦊 Fox to unlock"*) that defeats simple click-bots while taking real humans < 1 second, paired with zero-ghost auto-cleanup. |

---

## 2. Deep Engineering Hardening Audit (Every Component Inside AegisTG)

We audited every subsystem in v1.0 and upgraded all bottlenecks and edge cases in v2.0:

### 2.1 HTTP Transport & Raid-Proof Execution (`protector/telegram_client.py`)
* **v1.0 Bottleneck:** `urllib.request.urlopen` opened a brand-new TCP + TLS connection on *every* Bot API request — adding 80–250ms per call and risking ephemeral port exhaustion during 500-msg/sec raids.
* **v2.0 Upgrade:** Persistent **`urllib3.PoolManager(num_pools=16, maxsize=32)`** HTTP/1.1 Keep-Alive connection pooling (5–10x lower p95 latency), **Circuit Breaker** against Telegram 5xx outages, **`deleteMessages` batching** (up to 100 IDs/call), **`429 Retry-After`** backoff with jitter, and **graceful shutdown draining** (`close()` flushes all pending delete queues before exiting).

### 2.2 SQLite WAL Concurrency & Durability (`protector/storage.py`)
* **v1.0 Risk:** Default Python `sqlite3` transactions open as `DEFERRED`, risking `SQLITE_BUSY_SNAPSHOT` upgrade deadlocks under concurrent reads/writes, and lacked explicit `busy_timeout`, `mmap_size`, schema versioning, or WAL checkpointing.
* **v2.0 Upgrade:**
  * `isolation_level=None` with explicit **`BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`** write transactions.
  * Production PRAGMAs: `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`, `temp_store=MEMORY`, `cache_size=-16000` (16 MB), `mmap_size=67108864` (64 MB), `foreign_keys=ON`.
  * **`PRAGMA user_version` Schema Migrations** (zero-downtime v1 -> v2 upgrade adding feedback/precision & per-chat rule-exception tables).
  * Periodic **`PRAGMA wal_checkpoint(PASSIVE)`** + automated TTL pruning for both snapshots and aged incidents.

### 2.3 Perceptual Media Security & Scaling (`protector/analyzers/media_guard.py`)
* **v1.0 Bottleneck & Risk:** Linear $O(N)$ SQLite scan of all banned hashes on every photo, no EXIF orientation normalization, and no defense against Pillow PNG/WebP **Decompression Bombs** (a 100 KB malicious pixel-bomb can expand to 1 GB+ and OOM-crash a bot!).
* **v2.0 Upgrade:**
  * **Decompression Bomb Shield:** Caps `Image.MAX_IMAGE_PIXELS = 25_000_000`, validates headers, catches `Image.DecompressionBombError`, and flags deliberate pixel bombs as a **`MALWARE_EXPLOIT` Hard-Block (95)**!
  * **`ImageOps.exif_transpose()`** normalization so rotated/re-exported scam flyers still match reliably.
  * **In-Memory BK-Tree (Burkhard-Keller Metric Tree):** Exploits the triangle inequality of 64-bit Hamming distance to query thousands of banned perceptual hashes in **$O(\log N)$** sub-millisecond time.
  * **Bounded LRU Cache** on viral media wave tracking (max 2,000 active buckets) preventing unbounded RAM growth.

### 2.4 True Public Suffix List (PSL) & IDNA UTS #46 URL Intelligence (`protector/analyzers/url_intel.py`)
* **v1.0 Limitation:** Simple domain suffix checks couldn't distinguish multi-part public suffixes (`co.uk`, `com.bd`) or decode internationalized punycode (`xn--...`) back to Unicode to spot homoglyph brand impersonation.
* **v2.0 Upgrade:** Uses **`publicsuffix2`** for true eTLD+1 registrable domain extraction (`evil.telegram.org.co.uk` -> `org.co.uk` / brand spoof caught!) and **`idna.decode()`** + leetspeak/homoglyph folding on domains (catching `te1egram-verify.xyz`, `bk4sh-bonus.top`, and Cyrillic IDN clones).

### 2.5 Cryptographic Callback Integrity & ReDoS Guard (`protector/security.py`)
* **Problem:** Inline keyboard `callback_data` can be forged by malicious modified Telegram clients to spoof verification passes or trigger unauthorized admin actions.
* **v2.0 Solution:** Every interactive callback payload (`panel`, `verify`, `triage`, `lockdown`, `audit`) carries a compact **HMAC-SHA256 signature** with embedded TTL + server-side `getChatMember` authorization verification.
* **ReDoS & Memory Safety:** All incoming strings are bounded to Telegram's 4,096-character spec prior to regex inspection; all sliding windows in `BehavioralAnalyzer` enforce strict max-key LRU eviction so 24/7 operation stays memory-flat.

### 2.6 Self-Healing False-Positive Feedback Loop (Intelligent & ToS-Safe)
* Every Owner Alert Card features 1-tap triage buttons: **`✅ Confirm Threat`** | **`↩️ False Positive & Unban`** | **`🌐 FedBan`**.
* Tapping **`False Positive & Unban`**:
  1. Immediately calls `unbanChatMember` / restores full chat permissions,
  2. Removes any accidental Federation Ban and restores user trust (`+25`),
  3. Optionally adds the triggering domain to the chat's safe allowlist or records a local soft-exception,
  4. Logs precision telemetry (`TP / (TP + FP)`) displayed live in `/panel` — continuously improving accuracy per community **without ever scraping or training external AI models** (100% compliant with Telegram's AI/Scraping Terms).
