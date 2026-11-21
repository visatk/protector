# AegisTG — Intelligent Telegram Group & Channel Protection System

**AegisTG** is a Principal-architected, 9-layer intelligent protection bot designed to protect legitimate Telegram **Groups**, **Linked Discussion Groups (Channel Comments)**, **Channel Direct Messages**, and **Broadcast Channels** from bans, `SCAM`/`FAKE` flags, raids, delayed sabotage, malware, and admin account compromise.

> **সংক্ষেপে (বাংলায়):** AegisTG একটি ৯-স্তরের বুদ্ধিমান সুরক্ষা সিস্টেম যা আপনার টেলিগ্রাম গ্রুপ, চ্যানেল এবং লিঙ্কড কমেন্ট গ্রুপকে বট রেইড, পুরোনো মেসেজ এডিট করে স্প্যাম/অবৈধ কন্টেন্ট ঢোকানো (Edit-Bait), ফেক সেফগার্ড ফিশিং, বাংলা ও ইংরেজি স্ক্যাম, ক্ষতিকর APK/ম্যালওয়্যার, DMCA কপিরাইট ঝুঁকি এবং হ্যাকড অ্যাডমিন আক্রমণ থেকে রিয়েল-টাইমে রক্ষা করে।

---

## Documentation & Deep Research

1. **[Telegram Policy, Privacy, Security & Enforcement Deep Research](docs/TELEGRAM_POLICY_RESEARCH.md)**
   - Telegram Terms of Service, Privacy Policy (Section 8.3 law enforcement rules), Bot Developer Terms, 2024–2026 moderation surge (43.5M+ blocks/year), the 4-Tier Enforcement Model, and User/Group/Channel Security Guidelines.
2. **[Principal System Architecture & Design Blueprint](docs/SYSTEM_ARCHITECTURE.md)**
   - Mermaid diagrams, 9-layer defense pipeline, Raid State Machine, Edit-Bait Forensics, Rate-Limited `deleteMessages` batch execution, and scaling topology.
3. **[Bot Privacy Policy Template (ToS Sec 4 Compliant)](docs/PRIVACY_POLICY_TEMPLATE.md)**
   - Ready-to-host privacy policy strictly enforcing Telegram's zero-scraping / no-AI-training mandate.

---

## Quick Start

### 1. Run Offline Red-Team Simulation (No Token Needed)
Verify all 15 real-world attack & zero-false-positive benign scenarios right now:
```bash
python3 -m protector simulate
```

### 2. Offline Pre-Publish Channel Compliance Check
Test any channel draft before publishing to subscribers:
```bash
python3 -m protector check "Download HD 1080p free movie & cracked software here" --chat-type channel
```

### 3. Run Full Automated Test Suite
```bash
python3 -m unittest discover -s tests -v
```

### 4. Deploy Live on Telegram
1. Create a bot via `@BotFather`:
   - Turn **Group Privacy OFF** (`/setprivacy` -> Disable)
   - Register your **Privacy Policy URL** (`/mybots` -> Edit Privacy Policy)
2. Copy `.env.example` to `.env` and set `TELEGRAM_BOT_TOKEN` (and optionally `AEGIS_OWNER_ALERT_CHAT_ID`).
3. Add the bot as **Administrator** to BOTH your **Broadcast Channel** AND its **Linked Discussion Group** with:
   - `Delete Messages`, `Ban/Restrict Users`, `Invite Users via Link` (and `Manage Direct Messages` if enabled).
4. Start the bot:
   ```bash
   # Long Polling Mode
   python3 -m protector run

   # Or Secure Webhook Mode (requires TLS reverse proxy + AEGIS_WEBHOOK_SECRET)
   python3 -m protector webhook
   ```
5. Run `/audit` inside your group and channel to get your **0–100 Security Posture Score** and fix any missing Telegram native protections (Aggressive Anti-Spam, Slow Mode, Linked Group Parity, Admin Least-Privilege).

---

## Key Admin Commands

| Command | Purpose |
|---|---|
| `/audit` | Live 0–100 Security Health Audit of chat settings, admin privilege sprawl, and linked-group parity |
| `/draft <text>` | Pre-publish compliance scan for channel posts (checks DMCA, phishing, PII, ToS rules) |
| `/status` | Live Raid State (`NORMAL`/`ELEVATED`/`LOCKDOWN`) and 24h incident metrics |
| `/lockdown` / `/unlock` | Instant read-only emergency lockdown with exact permission snapshot & restore |
| `/strict_channel on\|off` | Auto-quarantine critical ToS/hijack posts inside broadcast channels |
| `/ban_media` | Reply to any scam/raid image to permanently ban its 64-bit perceptual dHash |
| `/fedban <id>` / `/fedunban <id>` | Sync bans instantly across your entire network of groups & channels |
| `/allow_domain <domain>` | Whitelist a trusted domain for a specific chat |
| `/set_alert_chat` | Route real-time hijack, raid, and critical threat alerts to a private owner chat |
| `/export_audit` | Generate a 30-day privacy-redacted compliance proof pack for `abuse@telegram.org` appeals |
| `/privacy` | Display bot Privacy Policy (Telegram Bot Developer ToS Section 4 compliance) |
