"""Secure Async Webhook & Observability Server (Secret-Token Auth + /health + /metrics)."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging

from protector.bot import ALLOWED_UPDATES, AegisTGBot

logger = logging.getLogger("aegistg.webhook")


class WebhookServer:
    """Lightweight asyncio HTTP webhook receiver with /health, /ready, and /metrics."""

    def __init__(self, bot: AegisTGBot, path: str = "/telegram/webhook") -> None:
        self.bot = bot
        self.path = path
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        cfg = self.bot.config
        await self.bot.initialize()
        if cfg.webhook_url:
            await self.bot.client.set_webhook(
                url=cfg.webhook_url,
                secret_token=cfg.webhook_secret_token or None,
                allowed_updates=ALLOWED_UPDATES,
            )
            logger.info("Webhook registered at %s", cfg.webhook_url)

        self._server = await asyncio.start_server(
            self._handle_connection, cfg.webhook_host, cfg.webhook_port
        )
        logger.info("Webhook HTTP server listening on %s:%s%s", cfg.webhook_host, cfg.webhook_port, self.path)
        try:
            async with self._server:
                await self._server.serve_forever()
        finally:
            await self.bot.shutdown()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
            lines = raw_head.decode("latin-1").split("\r\n")
            req_line = lines[0].split(" ")
            if len(req_line) < 2:
                await self._write_response(writer, 400, "Bad Request")
                return

            method, req_path = req_line[0], req_line[1]
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            if method == "GET" and req_path in {"/health", "/ready"}:
                await self._write_response(
                    writer,
                    200,
                    json.dumps({"status": "ok", "bot": self.bot.bot_username, "version": "2.0.0"}),
                    "application/json",
                )
                return

            if method == "GET" and req_path == "/metrics":
                await self._write_response(
                    writer,
                    200,
                    json.dumps(self.bot.metrics.snapshot(), indent=2),
                    "application/json",
                )
                return

            if method != "POST" or req_path != self.path:
                await self._write_response(writer, 404, "Not Found")
                return

            expected_secret = self.bot.config.webhook_secret_token
            if expected_secret:
                provided = headers.get("x-telegram-bot-api-secret-token", "")
                if not hmac.compare_digest(provided, expected_secret):
                    logger.warning("Rejected webhook request with invalid secret token")
                    await self._write_response(writer, 403, "Forbidden")
                    return

            content_length = int(headers.get("content-length", "0"))
            if content_length <= 0 or content_length > 2 * 1024 * 1024:
                await self._write_response(writer, 413, "Payload Too Large")
                return

            body = await asyncio.wait_for(reader.readexactly(content_length), timeout=10.0)
            update = json.loads(body.decode("utf-8"))

            await self._write_response(writer, 200, '{"ok":true}', "application/json")
            asyncio.create_task(self.bot.handle_update(update))
        except Exception as exc:
            logger.debug("Webhook connection error: %s", exc)
            try:
                await self._write_response(writer, 400, "Bad Request")
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _write_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body: str,
        content_type: str = "text/plain",
    ) -> None:
        reasons = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 413: "Payload Too Large"}
        payload = body.encode("utf-8")
        resp = (
            f"HTTP/1.1 {status} {reasons.get(status, 'Error')}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1") + payload
        writer.write(resp)
        await writer.drain()
