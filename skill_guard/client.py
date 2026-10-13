"""Thin client for calling Jev through OpenRouter's Decisions API."""

from __future__ import annotations

import os
import random
import time
from typing import Any

import requests

OPENROUTER_DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"
DEFAULT_MODEL = "~typesafe/jev-latest"


class JevClient:
    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL,
                 timeout: float = 120.0, max_retries: int = 5):
        self.api_key = api_key or os.environ["OPENROUTER_API_KEY"]
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries

    def ask(self, state: str | dict | list, questions: dict[str, Any]) -> dict[str, Any]:
        """Ask Jev one batch of questions, retrying transient failures.

        Rate limits (429), overload (529), and read timeouts are expected under
        concurrency rather than exceptional, so they are retried with exponential
        backoff plus jitter. Everything else surfaces immediately.
        """
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    OPENROUTER_DECISIONS_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={"model": self.model, "state": state, "questions": questions},
                    timeout=self.timeout,
                )
                if response.status_code in (429, 500, 502, 503, 529):
                    raise requests.HTTPError(f"retryable {response.status_code}", response=response)
                response.raise_for_status()
                return response.json()["answers"]
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
                status = getattr(exc.response, "status_code", None)
                if isinstance(exc, requests.HTTPError) and status not in (429, 500, 502, 503, 529):
                    raise
                last_error = exc
                if attempt < self.max_retries - 1:
                    time.sleep(min(2**attempt, 16) + random.random())
        raise RuntimeError(f"Jev request failed after {self.max_retries} attempts") from last_error
