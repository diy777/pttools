"""Web Agent — LLM-driven web application and API security testing.

Follows OWASP Testing Guide v4 methodology when LLM is available.
Falls back to deterministic tool loops otherwise.
"""

import asyncio
import logging
from typing import Any

from agents.base import BaseAgent, LLMUnavailableError
from engine.llm.client import LLMClient

logger = logging.getLogger("pentest-tools.web")


class WebAgent(BaseAgent):
    agent_type = "web"

    def __init__(self, registry: Any, db: Any, llm: LLMClient | None = None, scope: Any = None):
        super().__init__(registry, db, llm, scope=scope)

    async def run_assessment(
        self,
        target: str,
        auth_credentials: dict[str, str] | None = None,
        focus_areas: list[str] | None = None,
        engagement_id: str = "",
    ) -> dict[str, Any]:
        logger.info(f"Starting web assessment against {target}")

        if self.llm:
            areas = focus_areas or ["all"]
            if auth_credentials:
                cred_info = f"\nAuthentication credentials provided: {list(auth_credentials.keys())}"
            else:
                cred_info = "\nNo authentication credentials provided (testing unauthenticated)."
            prompt = (
                f"Run a web application security assessment against {target}.\n"
                f"Focus areas: {', '.join(areas)}\n"
                f"{cred_info}\n\n"
                f"Follow the OWASP Testing Guide methodology:\n"
                f"1. Content discovery and tech fingerprinting\n"
                f"2. Vulnerability scanning (nuclei, nikto)\n"
                f"3. Injection testing (SQLi, XSS, SSRF, command injection)\n"
                f"4. Authentication and session testing\n"
                f"5. API endpoint discovery and testing\n"
                f"6. Business logic testing (IDOR, race conditions)\n\n"
                f"Start with built-in scanners, then use external tools. Analyze results between phases."
            )
            try:
                return await self.run_tool_loop(prompt, engagement_id)
            except LLMUnavailableError:
                logger.warning("LLM unreachable; falling back to deterministic web assessment")

        return await self._run_deterministic(target, focus_areas, engagement_id)

    async def _run_deterministic(self, target: str, focus_areas: list[str] | None, engagement_id: str) -> dict[str, Any]:  # type: ignore[override]
        areas = focus_areas or ["all"]

        # Run discovery, fingerprinting, vuln scan, crawl-for-params, and a
        # parameter-discovery step (arjun) in parallel. The crawl + arjun
        # outputs both feed the injection phase below: sqlmap and dalfox need
        # URLs with parameters to attack, and modern targets (SPAs, parameter-
        # less REST endpoints) frequently expose nothing through the crawler
        # alone. arjun bruteforces hidden GET params on the base target so
        # injection has something to chew on even in those cases.
        # Phase 1: fingerprinting + content discovery + BrowserAgent crawl
        # + SPA probes. These are light-weight and don't hammer the target.
        # BrowserAgent (Playwright) runs here so it completes before the heavy
        # scanners (nuclei, nikto) start: avoids OOM on memory-constrained hosts.
        # SPA probes run early too, because they're cheap (under 5 seconds total)
        # and they catch criticals that disappear if the heavy scanners crash
        # the target before we get to them. They go BEFORE injection / fuzzing.
        discovery_tasks = [
            self._run_tool_phase(["gobuster", "ffuf", "feroxbuster", "dirsearch"], target, engagement_id, "content_discovery"),
            self._run_tool_phase(["whatweb", "wafw00f", "httpx"], target, engagement_id, "tech_fingerprint"),
        ]
        (content_result, fp_result), param_urls, spa_findings_count = await asyncio.gather(
            asyncio.gather(*discovery_tasks, return_exceptions=True),
            self._discover_param_urls(target),
            self._run_spa_probes(target, engagement_id, []),
        )

        # Phase 2: heavy vuln scanners + hidden param discovery.
        # Run after BrowserAgent so Playwright isn't competing for memory.
        vuln_tasks = [
            self._run_tool_phase(["nuclei", "nikto", "skipfish"], target, engagement_id, "vuln_scan"),
            self._discover_hidden_params(target, engagement_id),
        ]
        vuln_result, hidden_params = await asyncio.gather(*vuln_tasks, return_exceptions=True)
        if isinstance(hidden_params, Exception):
            hidden_params = []
        discovery_results = [content_result, fp_result, vuln_result]

        injection_targets = list(param_urls)
        # If the crawler found nothing useful but arjun discovered hidden
        # params, synthesize URLs from the base target + each discovered param.
        if not injection_targets and hidden_params:
            sep_target = target.rstrip("/")
            injection_targets = [
                f"{sep_target}/?{p}=1" for p in hidden_params[: self._MAX_INJECTION_TARGETS]
            ]
        # Even if the crawler found URLs, mix in arjun-discovered param URLs
        # against the base target so injection covers both spaces.
        elif hidden_params:
            sep_target = target.rstrip("/")
            extra = [f"{sep_target}/?{p}=1" for p in hidden_params[:5]]
            injection_targets = (injection_targets + extra)[: self._MAX_INJECTION_TARGETS]

        if not injection_targets:
            injection_targets = [target]

        injection_tasks: list[Any] = []
        if "sqli" in areas or "all" in areas:
            injection_tasks.append(self._run_injection_phase("sqlmap", injection_targets, engagement_id, "sqli"))
        if "xss" in areas or "all" in areas:
            injection_tasks.append(self._run_injection_phase("dalfox", injection_targets, engagement_id, "xss"))
        if "api" in areas or "all" in areas:
            injection_tasks.append(self._run_tool_phase(["kiterunner", "paramspider"], target, engagement_id, "api"))

        injection_results = await asyncio.gather(*injection_tasks, return_exceptions=True)

        # SPA probes already ran in Phase 1 (above), so we don't re-run here.
        # The earlier-run guarantees we capture critical findings even if the
        # injection phase ends up crashing or rate-limiting the target.

        all_results = list(discovery_results) + list(injection_results)
        total_findings = sum(r.get("findings_count", 0) for r in all_results if isinstance(r, dict))
        total_findings += spa_findings_count

        return {
            "target": target,
            "focus_areas": areas,
            "param_urls_discovered": len(param_urls),
            "hidden_params_discovered": len(hidden_params),
            "spa_probe_findings": spa_findings_count,
            "findings_count": total_findings,
            "status": "complete",
        }

    async def _run_spa_probes(
        self, target: str, engagement_id: str, param_urls: list[str]
    ) -> int:
        try:
            from agents.web.spa_probes import run_all_probes
        except ImportError as e:
            logger.warning("spa_probes import failed: %s", e)
            return 0
        # Pass any .js URLs the crawler saw so source-map probe has candidates.
        js_urls = [u for u in param_urls if ".js" in u]
        try:
            findings = await run_all_probes(target, js_urls=js_urls)
        except Exception as e:
            logger.warning("spa_probes run failed: %s", e)
            return 0
        for f in findings:
            f["engagement_id"] = engagement_id
            try:
                await self.db.add_finding(f)
            except Exception as e:
                logger.warning("spa_probe finding persist failed: %s", e)
        if findings:
            logger.info("spa_probes added %d findings", len(findings))
        return len(findings)

    # Per-tool wall-clock cap inside deterministic mode. nuclei + nikto need
    # ~60-90s to land real findings on a typical web app; the previous 30s was
    # too aggressive and produced zero findings on intentionally-vulnerable
    # targets like Juice Shop (the canonical training app). Per-tool timeout
    # here is the ceiling, individual tools still finish faster on small apps.
    _DETERMINISTIC_TOOL_TIMEOUT = 120.0

    # Crawler step is a setup phase, not a find-vulns phase. Cap shorter so the
    # injection phase doesn't sit waiting on a slow archive query.
    _CRAWL_TIMEOUT = 60.0

    # Cap parameterized URLs sent to sqlmap/dalfox. Each injection run can take
    # 30-120s; without a cap a chatty crawler can stretch the injection phase
    # to hours.
    _MAX_INJECTION_TARGETS = 20
    # URL substrings that are never useful injection targets: dynamic transport
    # tokens (socket.io, SockJS), asset hashes, health-check paths, etc.
    _NOISE_URL_SUBSTRINGS: tuple[str, ...] = (
        "socket.io",
        "sockjs",
        "/ws",
        "transport=polling",
        "transport=websocket",
        "/__webpack",
        "/_next/",
        "/__vite",
        "/static/",
        "/assets/",
        "/fonts/",
        "/images/",
        "favicon",
        ".map?",
        ".js?",
        ".css?",
    )

    # arjun bruteforces param names; on a small target it usually finishes in
    # 30-60s. Cap so it can't dominate the wall-clock for a single phase.
    _ARJUN_TIMEOUT = 90.0

    async def _run_tool_phase(self, tool_names: list[str], target: str, engagement_id: str, phase: str) -> dict[str, Any]:
        """Run all installed tools in this phase in parallel with a per-tool timeout.

        Previously ran sequentially; nuclei + nikto + skipfish in series could push
        a single phase past 5 minutes even with everything mocked. Parallel + 30s
        cap keeps a full deterministic web assessment under a minute.
        """
        installed = []
        for name in tool_names:
            tool = self.registry.get_tool(name) if self.registry else None
            if tool and tool.is_installed():
                installed.append((name, tool))

        if not installed:
            return {"phase": phase, "findings_count": 0}

        async def _run_one(name: str, tool: Any) -> list[dict[str, Any]]:
            try:
                # Push the timeout into tool.execute() instead of wrapping in
                # wait_for here. tool.execute() kills the subprocess on timeout;
                # wait_for would only cancel the await and orphan the subprocess,
                # which previously caused pttools to hang on shutdown.
                result = await tool.execute(target, timeout=self._DETERMINISTIC_TOOL_TIMEOUT)
                if result.get("exit_code") == -1:
                    logger.warning(f"{name} timed out after {self._DETERMINISTIC_TOOL_TIMEOUT}s in phase {phase}")
                return result.get("findings", []) or []
            except Exception as e:
                logger.warning(f"{name} failed in phase {phase}: {e}")
                return []

        findings_lists = await asyncio.gather(*[_run_one(n, t) for n, t in installed])
        findings_count = 0
        for findings in findings_lists:
            findings_count += len(findings)
            for f in findings:
                f["engagement_id"] = engagement_id
                await self.db.add_finding(f)
        return {"phase": phase, "findings_count": findings_count}

    async def _discover_param_urls(self, target: str) -> list[str]:
        """Run a crawler against the target and return URLs that have query params.

        Tries external crawlers in priority order (katana, hakrawler, gau).
        If they return nothing (typical for SPAs and hash-routed apps that
        external crawlers can't render), falls back to the BrowserAgent
        which uses Playwright to actually render the page and harvest:

        - XHR/fetch endpoints called during initial render
        - DOM links present after JS hydration
        - Hash-routed SPA URLs normalized to server-route form

        Returns an empty list if no crawler succeeds, in which case the caller
        falls back to the bare target.
        """
        for name in ("katana", "hakrawler", "gau"):
            tool = self.registry.get_tool(name) if self.registry else None
            if not tool or not tool.is_installed():
                continue
            try:
                result = await tool.execute(target, timeout=self._CRAWL_TIMEOUT)
            except Exception as e:
                logger.warning(f"crawler {name} failed: {e}")
                continue
            stdout = result.get("stdout", "") or ""
            seen: set[str] = set()
            urls: list[str] = []
            for raw in stdout.splitlines():
                line = raw.strip()
                if "?" not in line or not line.startswith(("http://", "https://")):
                    continue
                key = line.split("#", 1)[0]
                if key in seen:
                    continue
                seen.add(key)
                urls.append(line)
                if len(urls) >= self._MAX_INJECTION_TARGETS:
                    break
            if urls:
                logger.info(f"crawler {name} found {len(urls)} parameterized URLs to inject against")
                return urls
            logger.info(f"crawler {name} found no parameterized URLs, will try browser fallback")
            break

        # External crawler returned nothing useful (or none installed).
        # Run swagger spec parser and BrowserAgent in parallel for best coverage.
        swagger_urls, browser_urls = await asyncio.gather(
            self._discover_from_swagger(target),
            self._discover_param_urls_via_browser(target),
        )
        merged: list[str] = list(swagger_urls)
        seen_merged: set[str] = set(swagger_urls)
        for u in browser_urls:
            if u not in seen_merged:
                seen_merged.add(u)
                merged.append(u)
        if merged:
            if swagger_urls:
                logger.info(f"OpenAPI spec: {len(swagger_urls)} endpoints; BrowserAgent supplement: {len(browser_urls)} URLs")
            else:
                logger.info(f"BrowserAgent found {len(browser_urls)} parameterized URLs")
            return self._filter_injection_targets(merged)[: self._MAX_INJECTION_TARGETS]

        logger.info("no crawler produced parameterized URLs; injection phase will run against bare target")
        return []

    def _filter_injection_targets(self, urls: list[str]) -> list[str]:
        """Remove URLs that are useless for injection: dynamic transport tokens,
        asset URLs, and other noise that wastes injection budget.
        """
        clean: list[str] = []
        for url in urls:
            lower = url.lower()
            if any(noise in lower for noise in self._NOISE_URL_SUBSTRINGS):
                logger.debug(f"filtered noise URL from injection targets: {url[:80]}")
                continue
            clean.append(url)
        return clean

    async def _target_is_alive(self, target: str) -> bool:
        """Quick liveness check before running the injection phase.
        Returns True if the target responds to an HTTP request.
        """
        import urllib.error
        import urllib.request
        try:
            req = urllib.request.Request(target, headers={"User-Agent": "pttools-health-check/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status < 500
        except urllib.error.HTTPError as e:
            return e.code < 500
        except Exception:
            return False

    async def _discover_from_swagger(self, target: str) -> list[str]:
        """Fetch and parse OpenAPI / Swagger spec from well-known paths.
        Returns a list of parameterized URLs suitable for injection testing.
        Extracts GET endpoints that have query parameters defined in the spec.
        """
        import json
        import re
        import urllib.error
        import urllib.request

        base = target.rstrip("/")
        swagger_paths = [
            "/api-docs/swagger.yaml",
            "/api-docs",
            "/swagger.json",
            "/openapi.json",
            "/api/swagger.json",
            "/api/openapi.json",
            "/v1/swagger.json",
            "/api/v1/openapi.json",
            "/swagger/v1/swagger.json",
        ]
        spec: dict | None = None
        for path in swagger_paths:
            url = base + path
            try:
                req = urllib.request.Request(url, headers={"Accept": "application/json,application/yaml,text/yaml,*/*", "User-Agent": "pttools-api-discovery/1.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                # Try JSON first
                try:
                    spec = json.loads(raw)
                    logger.info(f"Found OpenAPI spec at {url}")
                    break
                except json.JSONDecodeError:
                    pass
                # Try YAML
                try:
                    import yaml  # type: ignore[import]
                    spec = yaml.safe_load(raw)
                    if isinstance(spec, dict) and ("paths" in spec or "openapi" in spec or "swagger" in spec):
                        logger.info(f"Found OpenAPI/Swagger YAML spec at {url}")
                        break
                    spec = None
                except Exception:
                    pass
            except (urllib.error.URLError, Exception):
                continue

        if not spec or not isinstance(spec, dict):
            return []

        # Determine base URL from spec servers or fall back to target
        server_base = base
        servers = spec.get("servers", [])
        if servers and isinstance(servers[0], dict):
            server_url = servers[0].get("url", "")
            if server_url.startswith("http"):
                server_base = server_url.rstrip("/")

        found: list[str] = []
        paths = spec.get("paths", {})
        for api_path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.lower() not in ("get",):
                    continue
                if not isinstance(op, dict):
                    continue
                params = op.get("parameters", [])
                query_params = [
                    p.get("name", "param")
                    for p in params
                    if isinstance(p, dict) and p.get("in") == "query"
                ]
                if query_params:
                    qs = "&".join(f"{n}=1" for n in query_params[:3])
                    full_path = api_path
                    # Replace path params with placeholder values
                    full_path = re.sub(r"\{[^}]+\}", "1", full_path)
                    url = server_base + full_path + "?" + qs
                    found.append(url)
                    if len(found) >= 30:
                        break
            if len(found) >= 30:
                break

        logger.info(f"Swagger parser extracted {len(found)} parameterized API endpoints")
        return found

    async def _discover_param_urls_via_browser(self, target: str) -> list[str]:
        """Use Playwright (via BrowserAgent) to render target and extract URLs.

        Optional: skipped silently if Playwright isn't installed (no
        pttools[browser] extra). Catches the SPA case where katana sees only
        the empty shell HTML and external crawlers find nothing.
        """
        try:
            from agents.browser.browser_agent import BrowserAgent
        except ImportError:
            return []
        try:
            agent = BrowserAgent(headless=True, timeout_ms=int(self._CRAWL_TIMEOUT * 1000))
            endpoints = await agent.crawl_for_endpoints(target, max_endpoints=50)
        except RuntimeError as e:
            # BrowserAgent raises RuntimeError when Playwright isn't installed.
            logger.info(f"browser-based crawler unavailable: {e}")
            return []
        except Exception as e:
            logger.warning(f"browser-based crawler failed: {e}")
            return []

        param_urls: list[str] = []
        seen: set[str] = set()
        for url in endpoints:
            if "?" not in url:
                continue
            key = url.split("#", 1)[0]
            if key in seen:
                continue
            seen.add(key)
            param_urls.append(url)
            if len(param_urls) >= self._MAX_INJECTION_TARGETS:
                break
        if param_urls:
            logger.info(
                f"browser crawler found {len(param_urls)} parameterized URLs from rendered DOM"
            )
        return param_urls

    async def _discover_hidden_params(self, target: str, engagement_id: str) -> list[str]:
        """Run arjun against the target's base URL to find hidden GET params.

        arjun bruteforces a wordlist of common param names against the URL,
        looking for response-delta or reflection signals. The returned param
        names are then synthesized into URLs the injection phase can attack.

        Persists the discovery as a finding so the audit + chaining stages
        know which params were considered. Returns an empty list if arjun is
        not installed, fails, or produces no params.
        """
        arjun = self.registry.get_tool("arjun") if self.registry else None
        if not arjun or not arjun.is_installed():
            return []
        try:
            result = await arjun.execute(target, timeout=self._ARJUN_TIMEOUT)
        except Exception as e:
            logger.warning(f"arjun param discovery failed: {e}")
            return []
        if result.get("exit_code") == -1:
            logger.warning("arjun param discovery timed out")
        for f in result.get("findings", []) or []:
            f["engagement_id"] = engagement_id
            await self.db.add_finding(f)
        # Re-extract param names from stdout for the injection synthesis;
        # we don't want to depend on the parser's exact finding shape.
        from tools.registry import _extract_arjun_params
        params = _extract_arjun_params(result.get("stdout", "") or "")
        if params:
            logger.info(f"arjun discovered {len(params)} hidden params: {params[:10]}")
        return params

    async def _run_injection_phase(
        self, tool_name: str, urls: list[str], engagement_id: str, phase: str
    ) -> dict[str, Any]:
        """Run an injection tool (sqlmap, dalfox) once per parameterized URL.

        Each URL runs in parallel with the same per-tool timeout used elsewhere.
        Findings are tagged with the engagement and persisted as usual.
        """
        tool = self.registry.get_tool(tool_name) if self.registry else None
        if not tool or not tool.is_installed():
            return {"phase": phase, "findings_count": 0}

        async def _run_one(url: str) -> list[dict[str, Any]]:
            try:
                result = await tool.execute(url, timeout=self._DETERMINISTIC_TOOL_TIMEOUT)
                if result.get("exit_code") == -1:
                    logger.warning(f"{tool_name} timed out on {url}")
                return result.get("findings", []) or []
            except Exception as e:
                logger.warning(f"{tool_name} failed on {url}: {e}")
                return []

        findings_lists = await asyncio.gather(*[_run_one(u) for u in urls])
        findings_count = 0
        for findings in findings_lists:
            findings_count += len(findings)
            for f in findings:
                f["engagement_id"] = engagement_id
                await self.db.add_finding(f)
        return {"phase": phase, "findings_count": findings_count, "targets_tested": len(urls)}
