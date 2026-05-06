"""Tests for engine/rate_limiter.py — Phase 1: Scan Intensity and Rate Control."""

import asyncio
import time

import pytest

from engine.rate_limiter import RateLimiter, ScanProfile


class TestScanProfile:
    def test_stealth_profile(self):
        p = ScanProfile.from_intensity("stealth")
        assert p.requests_per_second == 2.0
        assert p.max_concurrent_tools == 1
        assert p.delay_between_phases == 5.0
        assert p.tool_timeout_seconds == 300
        assert p.max_retries == 0

    def test_normal_profile(self):
        p = ScanProfile.from_intensity("normal")
        assert p.requests_per_second == 10.0
        assert p.max_concurrent_tools == 3
        assert p.tool_timeout_seconds == 120

    def test_aggressive_profile(self):
        p = ScanProfile.from_intensity("aggressive")
        assert p.requests_per_second == 0.0
        assert p.max_concurrent_tools == 10
        assert p.delay_between_phases == 0.0

    def test_unknown_falls_back_to_normal(self):
        p = ScanProfile.from_intensity("unknown")
        assert p.requests_per_second == 10.0

    def test_frozen(self):
        p = ScanProfile.from_intensity("normal")
        with pytest.raises(AttributeError):
            p.requests_per_second = 999


class TestRateLimiter:
    def test_create(self):
        profile = ScanProfile.from_intensity("normal")
        rl = RateLimiter(profile)
        assert rl.profile == profile

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self):
        profile = ScanProfile(
            requests_per_second=0.0,
            max_concurrent_tools=2,
            delay_between_phases=0.0,
            tool_timeout_seconds=60,
        )
        rl = RateLimiter(profile)

        running = []
        max_concurrent = 0

        async def work(i):
            nonlocal max_concurrent
            async with rl:
                running.append(i)
                if len(running) > max_concurrent:
                    max_concurrent = len(running)
                await asyncio.sleep(0.01)
                running.remove(i)

        await asyncio.gather(*[work(i) for i in range(5)])
        assert max_concurrent <= 2

    @pytest.mark.asyncio
    async def test_rate_limiting_throttles(self):
        profile = ScanProfile(
            requests_per_second=100.0,
            max_concurrent_tools=10,
            delay_between_phases=0.0,
            tool_timeout_seconds=60,
        )
        rl = RateLimiter(profile)

        start = time.monotonic()
        for _ in range(3):
            async with rl:
                pass
        elapsed = time.monotonic() - start
        assert elapsed >= 0.01

    @pytest.mark.asyncio
    async def test_no_rate_limit_when_zero_rps(self):
        profile = ScanProfile(
            requests_per_second=0.0,
            max_concurrent_tools=10,
            delay_between_phases=0.0,
            tool_timeout_seconds=60,
        )
        rl = RateLimiter(profile)

        start = time.monotonic()
        for _ in range(10):
            async with rl:
                pass
        elapsed = time.monotonic() - start
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_acquire_release(self):
        profile = ScanProfile.from_intensity("normal")
        rl = RateLimiter(profile)
        await rl.acquire()
        rl.release()
