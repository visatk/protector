# AegisTG v2.0 — Intelligent Telegram Group & Channel Protection System

**AegisTG v2.0** is a Principal-architected, 9-layer intelligent protection bot with a **first-party native Telegram UX** that protects legitimate **Groups**, **Linked Discussion Groups (Channel Comments)**, **Channel Direct Messages**, and **Broadcast Channels** from bans, `SCAM`/`FAKE` flags, raids, delayed edit-bait sabotage, malware, pixel-bomb DoS, and admin account compromise.

> **সংক্ষেপে (বাংলায়):** AegisTG v2.0 একটি ৯-স্তরের বুদ্ধিমান সুরক্ষা সিস্টেম — যার রয়েছে আধুনিক টেলিগ্রাম নেটিভ কন্ট্রোল প্যানেল (`/panel`), ১-ট্যাপ চ্যাট পিকার (`/connect`), ইমোজি হিউম্যান ভেরিফিকেশন, ইনলাইন লিংক স্ক্যানার (`@BotName`), ১-ট্যাপ ফলস-পজিটিভ সেলফ-হিলিং আনব্যান, এবং BK-Tree ও HTTP কানেকশন পুলিং সমৃদ্ধ হাই-স্পিড সিকিউরিটি ইঞ্জিন।

---

## Documentation & Deep Research

1. **[Telegram Policy, Privacy, Security & Enforcement Deep Research](docs/TELEGRAM_POLICY_RESEARCH.md)**
   - Telegram ToS, Privacy Policy (Section 8.3), Bot Developer Terms, 2024–2026 moderation surge (43.5M+ blocks/yr), 4-Tier Enforcement Model, and User/Group/Channel OpSec.
2. **[Principal System Architecture & Design Blueprint](docs/SYSTEM_ARCHITECTURE.md)**
   - Mermaid diagrams, 9-layer defense pipeline, Raid State Machine, Edit-Bait Forensics, Rate-Limited `deleteMessages` batch execution, and scaling topology.
3. **[Native Telegram Bot UX, Style & Production Hardening Guide (v2.0)](docs/NATIVE_UX_AND_HARDENING.md)**
   - Bot API 7.x–10.x native design primitives (`InlineKeyboardButton.style`, `<blockquote expandable>`, `CopyTextButton`, `KeyboardButtonRequestChat`, `setMyDefaultAdministratorRights`, `BotCommandScope`, `setMessageReaction`, `message_effect_id`, Inline Security Scanner) + deep engineering upgrades (`urllib3.PoolManager`, SQLite `BEGIN IMMEDIATE`, BK-Tree, PSL/IDNA, Pillow Decompression-Bomb shield, HMAC callback signing, Self-Healing False-Positive Loop).
4. **[Bot Privacy Policy Template (ToS Sec 4 Compliant)](docs/PRIVACY_POLICY_TEMPLATE.md)**

---

## Quick Start

### 1. Run 18-Scenario Offline Red-Team Simulation (No Token Needed)
```bash
python3 -m protector simulate
```

### 2. Offline Pre-Publish Channel Compliance Check
```bash
python3 -m protector check "Download HD 1080p free movie & cracked software Adobe link" --chat-type channel
```

### 3. Run Full Automated Test Suite
```bash
python3 -m unittest discover -s tests -v
```

### 4. Deploy Live on Telegram
1. Create a bot via `@BotFather` (turn **Group Privacy OFF** via `/setprivacy`, enable **Inline Mode** via `/setinline`, and register your **Privacy Policy URL**).
2. Copy `.env.example` to `.env` and set `TELEGRAM_BOT_TOKEN` (and `AEGIS_WEBHOOK_SECRET` for HMAC signing & webhooks).
3. Start the bot:
   ```bash
   python3 -m protector run       # Long Polling
   python3 -m protector webhook   # Secure Webhook + /health + /metrics
   ```
4. Open the bot in DM and tap **`/start`** or **`/connect`** — admin rights are pre-filled automatically via `setMyDefaultAdministratorRights`!

---

## Delightful Native Features & Admin Commands

| Feature / Command | What It Does |
|---|---|
| `/start` & `/connect` | One-tap Onboarding Wizard (`startgroup` / `startchannel`) + Native Telegram Chat/Channel Picker (`KeyboardButtonRequestChat`) |
| `/panel` | Live Edit-in-Place **Control Center Dashboard** with colored buttons (`primary`/`success`/`danger`), progress bars, expandable blockquotes & live tabs (`Overview`, `Threats`, `Precision`, `OpSec`) |
| `@BotName <url/draft>` | **Inline Security Scanner** — verify suspicious links or draft posts directly inside *any* Telegram chat |
| `/audit` | Live 0–100 Group/Channel Security Posture Scorecard with `A+` Fortress Shield celebration effect |
| `/digest` | 7-Day Community Protection Digest with threat breakdown, latency, precision rate & 1-tap `Copy Summary` |
| `/draft <text>` | Pre-publish Channel Compliance Scanner with native emoji reaction feedback (`👍`/`👀`/`⚡`) |
| **1-Tap Self-Healing Triage** | Every Owner Alert Card includes HMAC-signed **`✅ Confirm Threat`**, **`↩️ False Positive & Unban`**, **`🌐 FedBan Network`**, and **`📋 Copy ID`** buttons |
| **Emoji Human Gate** | Language-independent 6-emoji challenge (*"Tap the 🦊 Fox"*) with auto-deleting prompts & 90s zero-ghost timeout |
| `/lockdown` / `/unlock` | Emergency read-only anti-raid lockdown with exact `ChatPermissions` snapshot & restore |
| `/ban_media` | Reply to any scam/raid image to permanently index its 64-bit dHash into the $O(\log N)$ **BK-Tree** |
| `/export_audit` | 30-day privacy-redacted compliance proof pack for `abuse@telegram.org` appeals |
