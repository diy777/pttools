"""Rate limiter for controlling scan intensity."""

import asyncio
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    requests_per_second: float
    max_concurrent_tools: int
    delay_between_phases: float
    tool_timeout_seconds: int
    max_retries: int = 1

    @classmethod
    def from_intensity(cls, intensity: str) -> "ScanProfile":
        profiles = {
            "stealth": cls(
                requests_per_second=2.0,
                max_concurrent_tools=1,
                delay_between_phases=5.0,
                tool_timeout_seconds=300,
                max_retries=0,
            ),
            "normal": cls(
                requests_per_second=10.0,
                max_concurrent_tools=3,
                delay_between_phases=1.0,
                tool_timeout_seconds=120,
                max_retries=1,
            ),
            "aggressive": cls(
                requests_per_second=0.0,
                max_concurrent_tools=10,
                delay_between_phases=0.0,
                tool_timeout_seconds=60,
                max_retries=1,
            ),
        }
        return profiles.get(intensity, profiles["normal"])


class RateLimiter:
    def __init__(self, profile: ScanProfile):
        self._profile = profile
        self._semaphore = asyncio.Semaphore(profile.max_concurrent_tools)
        self._last_request = 0.0

    @property
    def profile(self) -> ScanProfile:
        return self._profile

    async def acquire(self) -> None:
        await self._semaphore.acquire()
        if self._profile.requests_per_second > 0:
            interval = 1.0 / self._profile.requests_per_second
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < interval:
                await asyncio.sleep(interval - elapsed)
            self._last_request = time.monotonic()

    def release(self) -> None:
        self._semaphore.release()

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.release()
