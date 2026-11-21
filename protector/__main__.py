"""CLI entrypoint for AegisTG Telegram Protector."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time

from protector.bot import AegisTGBot
from protector.config import load_config
from protector.engine import ProtectionEngine
from protector.models import ChatType, EventType, TelegramEvent
from protector.simulate import main as run_simulate_main
from protector.storage import Storage
from protector.webhook import WebhookServer


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )


async def _cmd_check(text: str, chat_type_str: str, policy_path: str | None) -> int:
    cfg = load_config(policy_path)
    storage = Storage(":memory:")
    engine = ProtectionEngine(cfg, storage)
    ev = TelegramEvent(
        event_type=EventType.DRAFT_CHECK,
        chat_id=-1000000000001,
        chat_type=ChatType(chat_type_str),
        timestamp=time.time(),
        text=text,
        is_admin=(chat_type_str == "channel"),
    )
    res = await engine.evaluate(ev)
    print(f"Verdict    : {res.action.value}")
    print(f"Risk Score : {res.risk_score}/100")
    print(f"Latency    : {res.latency_ms:.2f} ms")
    print(f"Summary    : {res.summary}")
    for sig in res.signals:
        print(f"  - [{sig.layer}:{sig.category.value}] (+{sig.score}) {sig.reason}")
    storage.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="protector",
        description="AegisTG — Intelligent Telegram Group & Channel Protection System",
    )
    parser.add_argument("--policy", default=None, help="Path to custom YAML policy file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Run bot in Long Polling mode (requires TELEGRAM_BOT_TOKEN)")
    sub.add_parser("webhook", help="Run bot in secure Webhook HTTP server mode")
    sub.add_parser("simulate", help="Run 15-scenario Red-Team attack & benign simulation benchmark")

    chk = sub.add_parser("check", help="Offline pre-publish compliance check for a draft message/post")
    chk.add_argument("text", help="Draft message or channel post text to analyze")
    chk.add_argument("--chat-type", choices=["channel", "supergroup"], default="channel")

    args = parser.parse_args()
    _setup_logging(args.verbose)

    if args.command == "simulate":
        return run_simulate_main()

    if args.command == "check":
        return asyncio.run(_cmd_check(args.text, args.chat_type, args.policy))

    cfg = load_config(args.policy)
    if not cfg.bot_token:
        print(
            "ERROR: TELEGRAM_BOT_TOKEN environment variable is required to run the live bot.\n"
            "Tip: Run `python3 -m protector simulate` to test the full protection engine offline.",
            file=sys.stderr,
        )
        return 2

    bot = AegisTGBot(cfg)
    if args.command == "run":
        try:
            asyncio.run(bot.run_polling())
        except KeyboardInterrupt:
            bot.stop()
        return 0

    if args.command == "webhook":
        server = WebhookServer(bot)
        try:
            asyncio.run(server.start())
        except KeyboardInterrupt:
            bot.stop()
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
