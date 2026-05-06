"""Tests for webhook notification system."""

from unittest.mock import MagicMock, patch

from engine.webhooks import WebhookNotifier, create_notifier_from_env


class TestWebhookNotifier:
    def test_no_url_returns_false(self):
        notifier = WebhookNotifier(url="")
        assert notifier.notify("engagement.started", {"target": "10.0.0.1"}) is False

    def test_filtered_event_returns_false(self):
        notifier = WebhookNotifier(url="http://example.com", events={"engagement.started"})
        assert notifier.notify("finding.new", {"target": "10.0.0.1"}) is False

    @patch("engine.webhooks.urlopen")
    def test_successful_delivery(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        notifier = WebhookNotifier(url="http://example.com/webhook")
        result = notifier.notify("engagement.started", {"target": "10.0.0.1"})
        assert result is True
        mock_urlopen.assert_called_once()

    @patch("engine.webhooks.urlopen", side_effect=Exception("Connection refused"))
    def test_delivery_failure_returns_false(self, mock_urlopen):
        notifier = WebhookNotifier(url="http://example.com/webhook")
        result = notifier.notify("engagement.started", {"target": "10.0.0.1"})
        assert result is False

    def test_slack_format(self):
        notifier = WebhookNotifier(url="http://slack.example.com", webhook_type="slack")
        payload = notifier._format_payload("finding.critical", {"target": "10.0.0.1", "severity": "critical", "title": "SQLi"})
        assert "text" in payload
        assert "CRITICAL" in payload["text"]
        assert "SQLi" in payload["text"]

    def test_generic_format(self):
        notifier = WebhookNotifier(url="http://example.com")
        payload = notifier._format_payload("engagement.started", {"target": "10.0.0.1"})
        assert payload["event"] == "engagement.started"
        assert payload["data"]["target"] == "10.0.0.1"


class TestCreateNotifierFromEnv:
    @patch.dict("os.environ", {"PENTEST_WEBHOOK_URL": "http://example.com/hook"})
    def test_creates_notifier_with_url(self):
        notifier = create_notifier_from_env()
        assert notifier is not None
        assert notifier.url == "http://example.com/hook"

    @patch.dict("os.environ", {}, clear=True)
    def test_returns_none_without_url(self):
        notifier = create_notifier_from_env()
        assert notifier is None

    @patch.dict("os.environ", {"PENTEST_WEBHOOK_URL": "http://x.com", "PENTEST_WEBHOOK_TYPE": "slack"})
    def test_reads_webhook_type(self):
        notifier = create_notifier_from_env()
        assert notifier.webhook_type == "slack"
