# AegisTG Protector Bot — Privacy Policy

> **Compliance Notice:** Published in accordance with Section 4 of the [Telegram Bot Platform Developer Terms of Service](https://telegram.org/tos/bots) and Telegram's Content Licensing & AI Scraping Terms. Register the public URL of this policy via `@BotFather` (`/setprivacy` / `/mybots` -> Edit Privacy Policy).

**Effective Date:** 2026-11-21

## 1. Purpose of Data Processing
AegisTG processes Telegram updates **strictly and exclusively** to protect participating groups, linked discussion groups, and channels against spam, raids, phishing, malware, illegal content contamination, and Terms of Service violations.

## 2. What Data We Process
- **Transient Inspection (In-Memory Only):** Message text, captions, URLs, file metadata, and image thumbnails are inspected in RAM to calculate a safety risk score and immediately discarded after evaluation.
- **Minimal Persistent Security Metadata (Stored Locally):**
  - Numeric Telegram `chat_id` and `user_id` identifiers
  - User behavioral trust scores, warning/strike counts, and local Federation ban flags
  - Cryptographic message hashes (`SHA-256`) and lightweight structural fingerprints (URL count, text length, timestamp) strictly for **Edit-Bait sabotage detection** (automatically purged after 7 days)
  - Perceptual image hashes (`64-bit dHash`, non-reversible mathematical fingerprints) of confirmed spam/raid flyers
  - Redacted moderation audit records (policy category, risk score, action taken, timestamp — **raw message content is NOT permanently stored**)

## 3. Strict No-AI-Training & No-Scraping Guarantee
- AegisTG **NEVER** scrapes, aggregates, sells, shares, or uses Telegram messages, media, or user metadata to train, fine-tune, validate, or benchmark any AI or machine learning model.
- If a group administrator explicitly opts into optional external semantic moderation for ambiguous messages, only the single isolated, PII-redacted text snippet is sent via zero-data-retention inference APIs solely for real-time safety classification.

## 4. Data Retention & Deletion Rights
- Edit-bait message fingerprints auto-expire after **7 days**.
- Redacted security audit logs auto-expire after **90 days** (configurable by the chat owner).
- Group owners may purge all data for their chat at any time by removing the bot and requesting deletion from the operator, or running `/purge_chat_data`.
- Users may request removal of non-ban metadata by contacting the bot operator listed in the bot profile.

## 5. Security Controls
- Webhook endpoints enforce TLS and validate `X-Telegram-Bot-Api-Secret-Token`.
- Access to the database and bot credentials is restricted to the system operator using least-privilege controls.

## 6. Developer & Operator Contact
- **Telegram:** [@drkingbd](https://t.me/drkingbd)
- **Website:** [https://drkingbd.cc](https://drkingbd.cc)
