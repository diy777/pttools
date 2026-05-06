"""Browser automation agent for headless web pentest workflows.

Drives a real browser (Playwright + Chromium) for:
  - DOM analysis and form discovery
  - Screenshot capture per page
  - Network request capture (URLs, headers, status codes)
  - JavaScript console error monitoring
  - Cookie and storage inspection
  - Authenticated session navigation

Closes a real gap with hexstrike, which has Selenium-based browser
automation as a headline feature. Playwright is faster, more modern,
and supports anti-detection out of the box.
"""

from agents.browser.browser_agent import BrowserAgent

__all__ = ["BrowserAgent"]
