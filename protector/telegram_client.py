"""Rate-Limit-Aware Async Telegram Bot API Client with Batch deleteMessages & 429 Backoff."""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from typing import Any

from protector.config import RateLimitsConfig

logger = logging.getLogger("aegistg.telegram")


class TelegramAPIError(RuntimeError):
    """Raised when Telegram Bot API returns an error response."""

    def __init__(self, method: str, code: int, description: str, retry_after: int | None = None):
        super().__init__(f"Telegram API {method} failed ({code}): {description}")
        self.method = method
        self.code = code
        self.description = description
        self.retry_after = retry_after


class AsyncTokenBucket:
    """Async token bucket rate limiter preventing 429 API exhaustion during raids."""

    def __init__(self, rate_per_sec: float, capacity: float | None = None) -> None:
        self.rate = max(0.1, rate_per_sec)
        self.capacity = capacity if capacity is not None else max(1.0, rate_per_sec)
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_s = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(wait_s)


class TelegramAPIClient:
    """Production async Bot API client supporting Cloud API & Local Bot API Server."""

    def __init__(
        self,
        bot_token: str,
        api_base_url: str = "https://api.telegram.org",
        rate_limits: RateLimitsConfig | None = None,
    ) -> None:
        self.bot_token = bot_token
        self.api_base_url = api_base_url.rstrip("/")
        self.rate_limits = rate_limits or RateLimitsConfig()

        self._global_bucket = AsyncTokenBucket(
            rate_per_sec=self.rate_limits.global_requests_per_second,
            capacity=self.rate_limits.global_requests_per_second,
        )
        self._chat_send_windows: dict[int, deque[float]] = defaultdict(deque)
        self._chat_backoff_until: dict[int, float] = {}

        # Coalesced batch deleteMessages buffers: chat_id -> list[message_id]
        self._delete_queues: dict[int, list[int]] = defaultdict(list)
        self._delete_tasks: dict[int, asyncio.Task[None]] = {}

    def _endpoint(self, method: str) -> str:
        return f"{self.api_base_url}/bot{self.bot_token}/{method}"

    async def call(
        self,
        method: str,
        payload: dict[str, Any] | None = None,
        timeout: float = 20.0,
        chat_id: int | None = None,
        is_outbound_message: bool = False,
    ) -> Any:
        payload = {k: v for k, v in (payload or {}).items() if v is not None}

        # Honor per-chat 429 cooldown
        if chat_id is not None:
            wait_until = self._chat_backoff_until.get(chat_id, 0.0)
            now = time.monotonic()
            if wait_until > now:
                await asyncio.sleep(wait_until - now)

        # Honor per-chat outbound message ceiling (default 18/min < Telegram's 20/min group limit)
        if is_outbound_message and chat_id is not None:
            await self._wait_chat_message_slot(chat_id)

        last_err: Exception | None = None
        for attempt in range(self.rate_limits.max_retries + 1):
            await self._global_bucket.acquire()
            try:
                return await asyncio.to_thread(self._http_post, method, payload, timeout)
            except TelegramAPIError as exc:
                last_err = exc
                if exc.code == 429 and attempt < self.rate_limits.max_retries:
                    retry_s = (exc.retry_after or 2) + random.uniform(0.15, 0.65)
                    logger.warning(
                        "Telegram 429 on %s (chat=%s); backing off %.2fs",
                        method,
                        chat_id,
                        retry_s,
                    )
                    if chat_id is not None:
                        self._chat_backoff_until[chat_id] = time.monotonic() + retry_s
                    await asyncio.sleep(retry_s)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError) as exc:
                last_err = exc
                if attempt < self.rate_limits.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                raise

        if last_err:
            raise last_err
        return None

    async def _wait_chat_message_slot(self, chat_id: int) -> None:
        dq = self._chat_send_windows[chat_id]
        limit = self.rate_limits.per_chat_messages_per_minute
        while True:
            now = time.monotonic()
            while dq and now - dq[0] >= 60.0:
                dq.popleft()
            if len(dq) < limit:
                dq.append(now)
                return
            sleep_for = max(0.1, 60.0 - (now - dq[0]) + 0.05)
            await asyncio.sleep(sleep_for)

    def _http_post(self, method: str, payload: dict[str, Any], timeout: float) -> Any:
        url = self._endpoint(method)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                parsed = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(body)
            except json.JSONDecodeError:
                err_json = {"error_code": exc.code, "description": body[:200]}
            retry_after = (err_json.get("parameters") or {}).get("retry_after")
            raise TelegramAPIError(
                method=method,
                code=int(err_json.get("error_code", exc.code)),
                description=str(err_json.get("description", exc.reason)),
                retry_after=int(retry_after) if retry_after is not None else None,
            ) from exc

        if not parsed.get("ok"):
            retry_after = (parsed.get("parameters") or {}).get("retry_after")
            raise TelegramAPIError(
                method=method,
                code=int(parsed.get("error_code", 400)),
                description=str(parsed.get("description", "Unknown Telegram error")),
                retry_after=int(retry_after) if retry_after is not None else None,
            )
        return parsed.get("result")

    # ------------------------------------------------------------------
    # Coalesced Batch Deletion (Up to 100 Messages per Bot API Call!)
    # ------------------------------------------------------------------
    async def queue_delete_message(self, chat_id: int, message_id: int) -> None:
        buf = self._delete_queues[chat_id]
        if message_id not in buf:
            buf.append(message_id)
        if len(buf) >= self.rate_limits.max_delete_batch_size:
            await self.flush_delete_queue(chat_id)
            return
        if chat_id not in self._delete_tasks or self._delete_tasks[chat_id].done():
            self._delete_tasks[chat_id] = asyncio.create_task(self._delayed_flush(chat_id))

    async def _delayed_flush(self, chat_id: int) -> None:
        await asyncio.sleep(self.rate_limits.delete_batch_window_ms / 1000.0)
        await self.flush_delete_queue(chat_id)

    async def flush_delete_queue(self, chat_id: int) -> None:
        buf = self._delete_queues.get(chat_id)
        if not buf:
            return
        batch = buf[: self.rate_limits.max_delete_batch_size]
        del buf[: len(batch)]
        try:
            if len(batch) == 1:
                await self.delete_message(chat_id, batch[0])
            else:
                await self.delete_messages(chat_id, batch)
        except TelegramAPIError as exc:
            logger.debug("Batch delete warning in chat %s: %s", chat_id, exc)

    # ------------------------------------------------------------------
    # Bot API Method Wrappers
    # ------------------------------------------------------------------
    async def get_me(self) -> dict[str, Any]:
        return await self.call("getMe")

    async def get_updates(
        self, offset: int | None = None, timeout: int = 25, allowed_updates: list[str] | None = None
    ) -> list[dict[str, Any]]:
        return await self.call(
            "getUpdates",
            {"offset": offset, "timeout": timeout, "allowed_updates": allowed_updates},
            timeout=timeout + 10.0,
        )

    async def set_webhook(
        self, url: str, secret_token: str | None = None, allowed_updates: list[str] | None = None
    ) -> bool:
        return await self.call(
            "setWebhook",
            {
                "url": url,
                "secret_token": secret_token or None,
                "allowed_updates": allowed_updates,
                "drop_pending_updates": False,
            },
        )

    async def delete_webhook(self, drop_pending_updates: bool = False) -> bool:
        return await self.call("deleteWebhook", {"drop_pending_updates": drop_pending_updates})

    async def set_my_commands(self, commands: list[dict[str, str]]) -> bool:
        return await self.call("setMyCommands", {"commands": commands})

    async def send_message(
        self,
        chat_id: int,
        text: str,
        parse_mode: str | None = "HTML",
        reply_to_message_id: int | None = None,
        reply_markup: dict[str, Any] | None = None,
        disable_web_page_preview: bool = True,
    ) -> dict[str, Any]:
        return await self.call(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": text[:4096],
                "parse_mode": parse_mode,
                "reply_to_message_id": reply_to_message_id,
                "reply_markup": reply_markup,
                "disable_web_page_preview": disable_web_page_preview,
            },
            chat_id=chat_id,
            is_outbound_message=True,
        )

    async def delete_message(self, chat_id: int, message_id: int) -> bool:
        return await self.call(
            "deleteMessage",
            {"chat_id": chat_id, "message_id": message_id},
            chat_id=chat_id,
        )

    async def delete_messages(self, chat_id: int, message_ids: list[int]) -> bool:
        return await self.call(
            "deleteMessages",
            {"chat_id": chat_id, "message_ids": message_ids[:100]},
            chat_id=chat_id,
        )

    async def ban_chat_member(
        self,
        chat_id: int,
        user_id: int,
        until_date: int | None = None,
        revoke_messages: bool = True,
    ) -> bool:
        return await self.call(
            "banChatMember",
            {
                "chat_id": chat_id,
                "user_id": user_id,
                "until_date": until_date,
                "revoke_messages": revoke_messages,
            },
            chat_id=chat_id,
        )

    async def restrict_chat_member(
        self,
        chat_id: int,
        user_id: int,
        permissions: dict[str, bool],
        until_date: int | None = None,
        use_independent_chat_permissions: bool = True,
    ) -> bool:
        return await self.call(
            "restrictChatMember",
            {
                "chat_id": chat_id,
                "user_id": user_id,
                "permissions": permissions,
                "until_date": until_date,
                "use_independent_chat_permissions": use_independent_chat_permissions,
            },
            chat_id=chat_id,
        )

    async def ban_chat_sender_chat(self, chat_id: int, sender_chat_id: int) -> bool:
        return await self.call(
            "banChatSenderChat",
            {"chat_id": chat_id, "sender_chat_id": sender_chat_id},
            chat_id=chat_id,
        )

    async def set_chat_permissions(
        self,
        chat_id: int,
        permissions: dict[str, bool],
        use_independent_chat_permissions: bool = True,
    ) -> bool:
        return await self.call(
            "setChatPermissions",
            {
                "chat_id": chat_id,
                "permissions": permissions,
                "use_independent_chat_permissions": use_independent_chat_permissions,
            },
            chat_id=chat_id,
        )

    async def approve_chat_join_request(self, chat_id: int, user_id: int) -> bool:
        return await self.call(
            "approveChatJoinRequest",
            {"chat_id": chat_id, "user_id": user_id},
            chat_id=chat_id,
        )

    async def decline_chat_join_request(self, chat_id: int, user_id: int) -> bool:
        return await self.call(
            "declineChatJoinRequest",
            {"chat_id": chat_id, "user_id": user_id},
            chat_id=chat_id,
        )

    async def get_chat(self, chat_id: int) -> dict[str, Any]:
        return await self.call("getChat", {"chat_id": chat_id}, chat_id=chat_id)

    async def get_chat_administrators(self, chat_id: int) -> list[dict[str, Any]]:
        return await self.call("getChatAdministrators", {"chat_id": chat_id}, chat_id=chat_id)

    async def get_file(self, file_id: str) -> dict[str, Any]:
        return await self.call("getFile", {"file_id": file_id})

    async def download_file_bytes(self, file_id: str, max_bytes: int = 5 * 1024 * 1024) -> bytes | None:
        info = await self.get_file(file_id)
        file_size = info.get("file_size", 0)
        file_path = info.get("file_path")
        if not file_path or (file_size and file_size > max_bytes):
            return None
        url = f"{self.api_base_url}/file/bot{self.bot_token}/{file_path}"

        def _dl() -> bytes:
            with urllib.request.urlopen(url, timeout=15.0) as resp:
                return resp.read(max_bytes + 1)

        data = await asyncio.to_thread(_dl)
        if len(data) > max_bytes:
            return None
        return data

    async def answer_callback_query(
        self, callback_query_id: str, text: str | None = None, show_alert: bool = False
    ) -> bool:
        return await self.call(
            "answerCallbackQuery",
            {"callback_query_id": callback_query_id, "text": text, "show_alert": show_alert},
        )
