"""T1 AI 辅助验证测试 — 2026-08-08.

覆盖：LLMClient 配置/可用性/请求构造、AIVerifier 确认/降级/批次/异常保持、
AI 报告提取与子命令。原则：无 key 或请求失败时零行为变化，复核只降级不删除。
"""

import json
from types import SimpleNamespace

import httpx
import pytest

from wvs.ai.client import LLMClient, extract_json, truncate
from wvs.ai.verifier import _SEVERITY_DOWNGRADE, AIVerifier, _build_items
from wvs.models import Severity, Vulnerability, VulnerabilityType

# =====================================================================
# LLMClient
# =====================================================================


class TestLLMClient:
    def test_not_available_without_key(self, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        assert LLMClient().available is False

    def test_available_with_env_key(self, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "sk-test")
        client = LLMClient()
        assert client.available is True
        assert client.base_url == "https://api.openai.com/v1"

    def test_available_with_config_key(self):
        from wvs.config import ConfigManager

        config = ConfigManager()
        config.set("ai.api_key", "sk-config")
        assert LLMClient(config).available is True

    def test_base_url_from_env(self, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "sk-test")
        monkeypatch.setenv("LLM_BASE_URL", "https://proxy.example.com/v1/")
        assert LLMClient().base_url == "https://proxy.example.com/v1"

    def test_chat_none_without_key(self):
        client = LLMClient(api_key="")
        assert client.available is False

    @pytest.mark.asyncio
    async def test_chat_returns_none_without_key(self, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        result = await LLMClient().chat([{"role": "user", "content": "hi"}])
        assert result is None

    @pytest.mark.asyncio
    async def test_chat_builds_request_and_parses(self, monkeypatch):
        """验证请求构造（端点/鉴权头/body）与响应解析。"""
        monkeypatch.delenv("LLM_API_KEY", raising=False)

        captured = {}

        def handler(request):
            captured["url"] = str(request.url)
            captured["auth"] = request.headers.get("Authorization")
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": '{"ok": 1}'}}]},
            )

        transport = httpx.MockTransport(handler)
        client = LLMClient(api_key="sk-test", model="gpt-4o", transport=transport)
        content = await client.chat([{"role": "user", "content": "hi"}], temperature=0.5)

        assert content == '{"ok": 1}'
        assert captured["url"] == "https://api.openai.com/v1/chat/completions"
        assert captured["auth"] == "Bearer sk-test"
        assert captured["body"]["model"] == "gpt-4o"
        assert captured["body"]["messages"][0]["content"] == "hi"
        assert captured["body"]["temperature"] == 0.5

    @pytest.mark.asyncio
    async def test_chat_returns_none_on_http_error(self):
        def handler(request):
            return httpx.Response(500, text="boom")

        client = LLMClient(api_key="sk-test", transport=httpx.MockTransport(handler))
        assert await client.chat([{"role": "user", "content": "hi"}]) is None

    @pytest.mark.asyncio
    async def test_chat_json_parses_content(self, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)

        def handler(request):
            return httpx.Response(200, json={"choices": [{"message": {"content": '```json\n{"a": 1}\n```'}}]})

        client = LLMClient(api_key="sk-test", transport=httpx.MockTransport(handler))
        parsed = await client.chat_json([{"role": "user", "content": "hi"}])
        assert parsed == {"a": 1}


class TestExtractJson:
    def test_plain(self):
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_wrapped_in_text(self):
        assert extract_json('Sure! {"a": 1} hope that helps') == {"a": 1}

    def test_malformed_returns_none(self):
        assert extract_json("no json here") is None
        assert extract_json('{"a": }') is None


class TestTruncate:
    def test_short_unchanged(self):
        assert truncate("abc", 5) == "abc"

    def test_long_truncated(self):
        assert truncate("abcdef", 3) == "abc..."
        assert truncate(None) == ""
        assert truncate(12345, 3) == "123..."


# =====================================================================
# AIVerifier
# =====================================================================


def _make_vuln(severity=Severity.MEDIUM, evidence="evidence", url="http://t/a?id=1"):
    return Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url=url,
        parameter="id",
        payload="' OR '1'='1",
        evidence=evidence,
        http_response="<html>SQL error near 'OR'</html>",
        severity=severity,
    )


class FakeLLMClient:
    """鸭子类型 LLM 客户端：按顺序吐预设 JSON，记录调用。"""

    available = True

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def chat_json(self, messages, **kwargs):
        self.calls.append(messages)
        return self._responses.pop(0) if self._responses else None


class TestAIVerifier:
    @pytest.mark.asyncio
    async def test_no_key_keeps_original(self, monkeypatch):
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        v = _make_vuln()
        verifier = AIVerifier(client=LLMClient())
        result = await verifier.verify_batch([v])
        assert result == [v]
        assert v.tags == []

    @pytest.mark.asyncio
    async def test_low_severity_not_sent(self):
        fake = FakeLLMClient([{}])
        v = _make_vuln(severity=Severity.INFO)
        verifier = AIVerifier(client=fake)
        result = await verifier.verify_batch([v])
        assert result == [v]
        assert fake.calls == []  # 不发送任何请求

    @pytest.mark.asyncio
    async def test_confirm_dispute_and_review(self):
        responses = [
            {
                "results": [
                    {"index": 0, "vulnerable": True, "confidence": 0.95, "reason": "evidence clear"},
                    {"index": 1, "vulnerable": False, "confidence": 0.1, "reason": "echo server"},
                    {"index": 2, "vulnerable": True, "confidence": 0.5, "reason": "uncertain"},
                ]
            }
        ]
        fake = FakeLLMClient(responses)
        v1 = _make_vuln()
        v2 = _make_vuln(url="http://t/echo?q=1")
        v3 = _make_vuln(url="http://t/other?q=1")
        verifier = AIVerifier(client=fake)
        await verifier.verify_batch([v1, v2, v3])

        # 确认：tag + confidence 提升
        assert "ai_confirmed" in v1.tags
        assert v1.severity == Severity.MEDIUM  # 严重度不变
        assert v1.context.get("ai_reviewed") is True
        assert v1.context["ai_verdict"]["vulnerable"] is True

        # 存疑：降级 + tag
        assert "ai_disputed" in v2.tags
        assert v2.severity == _SEVERITY_DOWNGRADE[Severity.MEDIUM]  # LOW
        assert v2.context["ai_verdict"]["vulnerable"] is False

        # 不确定：仅记录
        assert "ai_reviewed" in v3.tags
        assert v3.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_invalid_response_keeps_original(self):
        fake = FakeLLMClient([{"bad": "shape"}])
        v = _make_vuln()
        verifier = AIVerifier(client=fake)
        result = await verifier.verify_batch([v])
        assert result == [v]
        assert v.tags == []

    @pytest.mark.asyncio
    async def test_batches_split_by_five(self):
        fake = FakeLLMClient([{"results": []}, {"results": []}])
        vulns = [_make_vuln(url=f"http://t/{i}") for i in range(6)]
        verifier = AIVerifier(client=fake)
        await verifier.verify_batch(vulns)
        assert len(fake.calls) == 2  # 6 条 = 5 + 1 两批

    @pytest.mark.asyncio
    async def test_exception_in_chat_keeps_original(self):
        class BoomClient(FakeLLMClient):
            async def chat_json(self, messages, **kwargs):
                raise RuntimeError("boom")

        v = _make_vuln()
        verifier = AIVerifier(client=BoomClient([{}]))
        result = await verifier.verify_batch([v])
        assert result == [v]
        assert v.tags == []

    def test_build_items_truncates(self):
        items = _build_items([_make_vuln(evidence="x" * 5000, url="http://t/" + "y" * 500)])
        assert len(items[0]["evidence"]) <= 500 + 3
        assert len(items[0]["url"]) <= 200 + 3

    def test_downgrade_map(self):
        assert _SEVERITY_DOWNGRADE[Severity.CRITICAL] == Severity.HIGH
        assert _SEVERITY_DOWNGRADE[Severity.HIGH] == Severity.MEDIUM
        assert _SEVERITY_DOWNGRADE[Severity.MEDIUM] == Severity.LOW
        assert _SEVERITY_DOWNGRADE[Severity.LOW] == Severity.INFO
        assert _SEVERITY_DOWNGRADE[Severity.INFO] == Severity.INFO


# =====================================================================
# AI 报告（T1.3）
# =====================================================================


class TestAIReport:
    def test_extract_findings(self):
        from wvs.ai.report import _extract_findings

        report = {
            "vulnerabilities": [
                {"type": "sql_injection", "severity": "high", "title": "x", "url": "http://t", "evidence": "e" * 1000},
                "not-a-dict",
            ]
        }
        findings = _extract_findings(report)
        assert len(findings) == 1
        assert findings[0]["evidence"].endswith("...")  # 截断生效

    @pytest.mark.asyncio
    async def test_generate_none_without_key(self, monkeypatch):
        from wvs.ai.report import generate_ai_summary

        monkeypatch.delenv("LLM_API_KEY", raising=False)
        report = {"vulnerabilities": [{"type": "xss", "severity": "high"}]}
        assert await generate_ai_summary(report, LLMClient()) is None

    @pytest.mark.asyncio
    async def test_generate_none_without_findings(self, monkeypatch):
        from wvs.ai.report import generate_ai_summary

        monkeypatch.delenv("LLM_API_KEY", raising=False)
        assert await generate_ai_summary({"vulnerabilities": []}, LLMClient(api_key="sk-test")) is None


# =====================================================================
# CLI ai-report 子命令
# =====================================================================


class TestCmdAIReport:
    def test_missing_file_returns_1(self, tmp_path):
        from wvs.cli import cmd_ai_report

        args = SimpleNamespace(report=str(tmp_path / "nope.json"), output=None)
        assert cmd_ai_report(args) == 1

    def test_no_key_returns_1(self, tmp_path, monkeypatch):
        from wvs.cli import cmd_ai_report

        monkeypatch.delenv("LLM_API_KEY", raising=False)
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps({"vulnerabilities": [{"type": "xss"}]}), encoding="utf-8")
        args = SimpleNamespace(report=str(report_file), output=None)
        assert cmd_ai_report(args) == 1
