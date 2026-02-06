"""Tests for the proxy module."""

import httpx
import pytest
import respx

from clawpwn.modules.proxy import (
    InterceptProxy,
    ProxyEntry,
    ProxyStore,
    compare_responses,
    modify_and_send,
    replay_request,
)

# ── ProxyEntry ───────────────────────────────────────────────────


class TestProxyEntry:
    def test_defaults(self):
        entry = ProxyEntry()
        assert entry.id == 0
        assert entry.method == "GET"
        assert entry.url == ""
        assert entry.status_code == 0
        assert entry.request_headers == {}
        assert entry.tags == []

    def test_custom_values(self):
        entry = ProxyEntry(method="POST", url="http://x.com/api", status_code=201, tags=["flagged"])
        assert entry.method == "POST"
        assert entry.status_code == 201
        assert "flagged" in entry.tags

    def test_mutable_defaults_are_independent(self):
        a = ProxyEntry()
        b = ProxyEntry()
        a.tags.append("only-a")
        assert b.tags == []


# ── ProxyStore ───────────────────────────────────────────────────


class TestProxyStore:
    def test_add_and_get(self):
        store = ProxyStore()
        entry = store.add(ProxyEntry(url="http://a.com"))
        assert entry.id == 1
        assert store.get(1) is entry
        assert store.get(999) is None

    def test_auto_increment(self):
        store = ProxyStore()
        assert store.add(ProxyEntry()).id == 1
        assert store.add(ProxyEntry()).id == 2

    def test_len_and_entries_copy(self):
        store = ProxyStore()
        store.add(ProxyEntry())
        assert len(store) == 1
        store.entries.clear()
        assert len(store) == 1

    def test_eviction(self):
        store = ProxyStore(max_entries=3)
        for i in range(5):
            store.add(ProxyEntry(url=f"http://{i}.com"))
        assert len(store) == 3
        assert store.get(1) is None
        assert store.get(2) is None
        assert store.get(5) is not None

    def test_search_url(self):
        store = ProxyStore()
        store.add(ProxyEntry(url="http://example.com/login"))
        store.add(ProxyEntry(url="http://other.com"))
        assert len(store.search(url_pattern="example")) == 1

    def test_search_method(self):
        store = ProxyStore()
        store.add(ProxyEntry(method="GET"))
        store.add(ProxyEntry(method="POST"))
        assert len(store.search(method="post")) == 1

    def test_search_status(self):
        store = ProxyStore()
        store.add(ProxyEntry(status_code=200))
        store.add(ProxyEntry(status_code=404))
        assert len(store.search(status_code=404)) == 1

    def test_search_tag(self):
        store = ProxyStore()
        store.add(ProxyEntry(tags=["auth"]))
        store.add(ProxyEntry())
        assert len(store.search(tag="auth")) == 1

    def test_search_body(self):
        store = ProxyStore()
        store.add(ProxyEntry(response_body="token=abc"))
        store.add(ProxyEntry(response_body="nothing"))
        assert len(store.search(body_contains="token")) == 1

    def test_search_combined(self):
        store = ProxyStore()
        store.add(ProxyEntry(method="GET", status_code=200))
        store.add(ProxyEntry(method="POST", status_code=200))
        store.add(ProxyEntry(method="GET", status_code=404))
        results = store.search(method="GET", status_code=200)
        assert len(results) == 1

    def test_tag_entry(self):
        store = ProxyStore()
        store.add(ProxyEntry())
        assert store.tag(1, "flagged") is True
        assert "flagged" in store.get(1).tags
        assert store.tag(1, "flagged") is False  # duplicate ignored
        assert store.tag(999, "x") is False

    def test_annotate(self):
        store = ProxyStore()
        store.add(ProxyEntry())
        assert store.annotate(1, "suspicious") is True
        assert store.get(1).notes == "suspicious"
        assert store.annotate(999, "x") is False

    def test_clear(self):
        store = ProxyStore()
        store.add(ProxyEntry())
        store.add(ProxyEntry())
        assert store.clear() == 2
        assert len(store) == 0

    def test_clear_resets_ids(self):
        store = ProxyStore()
        store.add(ProxyEntry())
        store.clear()
        assert store.add(ProxyEntry()).id == 1

    def test_export(self):
        store = ProxyStore()
        store.add(ProxyEntry(method="GET", url="http://a.com"))
        data = store.export()
        assert len(data) == 1
        assert data[0]["method"] == "GET"
        assert data[0]["url"] == "http://a.com"
        assert "timestamp" in data[0]

    def test_export_truncates_body(self):
        store = ProxyStore()
        store.add(ProxyEntry(response_body="x" * 1000))
        assert len(store.export()[0]["response_body"]) == 500


# ── compare_responses ────────────────────────────────────────────


class TestCompareResponses:
    def test_identical(self):
        a = ProxyEntry(status_code=200, response_body="ok", response_headers={"X": "1"})
        b = ProxyEntry(status_code=200, response_body="ok", response_headers={"X": "1"})
        diff = compare_responses(a, b)
        assert diff["status_changed"] is False
        assert diff["body_changed"] is False
        assert diff["headers_added"] == []
        assert diff["headers_removed"] == []
        assert diff["headers_changed"] == []

    def test_status_change(self):
        diff = compare_responses(
            ProxyEntry(status_code=200),
            ProxyEntry(status_code=403),
        )
        assert diff["status_changed"] is True
        assert diff["original_status"] == 200
        assert diff["replayed_status"] == 403

    def test_body_change(self):
        diff = compare_responses(
            ProxyEntry(response_body="hello"),
            ProxyEntry(response_body="world"),
        )
        assert diff["body_changed"] is True
        assert diff["body_length_original"] == 5
        assert diff["body_length_replayed"] == 5

    def test_header_diff(self):
        a = ProxyEntry(response_headers={"X": "1", "Y": "2"})
        b = ProxyEntry(response_headers={"X": "changed", "Z": "3"})
        diff = compare_responses(a, b)
        assert "Z" in diff["headers_added"]
        assert "Y" in diff["headers_removed"]
        assert "X" in diff["headers_changed"]


# ── InterceptProxy lifecycle ─────────────────────────────────────


class TestInterceptProxy:
    def test_defaults(self):
        proxy = InterceptProxy()
        assert proxy.host == "127.0.0.1"
        assert proxy.port == 8080
        assert proxy.running is False
        assert isinstance(proxy.store, ProxyStore)

    def test_custom_store(self):
        store = ProxyStore(max_entries=10)
        proxy = InterceptProxy(store=store)
        assert proxy.store is store

    @pytest.mark.asyncio
    async def test_start_stop(self):
        proxy = InterceptProxy(port=0)  # OS picks a free port
        await proxy.start()
        assert proxy.running is True
        await proxy.stop()
        assert proxy.running is False

    def test_rule_management(self):
        proxy = InterceptProxy()
        proxy.add_rule(lambda e: e)
        assert len(proxy._rules) == 1
        proxy.clear_rules()
        assert len(proxy._rules) == 0


# ── replay / modify ──────────────────────────────────────────────


class TestReplay:
    @respx.mock
    @pytest.mark.asyncio
    async def test_replay_request(self):
        respx.get("http://target.com/page").mock(
            return_value=httpx.Response(200, text="replayed body"),
        )
        original = ProxyEntry(id=5, method="GET", url="http://target.com/page")
        result = await replay_request(original)
        assert result.status_code == 200
        assert result.response_body == "replayed body"
        assert "replayed" in result.tags
        assert "5" in result.notes

    @respx.mock
    @pytest.mark.asyncio
    async def test_replay_preserves_request_fields(self):
        respx.post("http://t.com/api").mock(
            return_value=httpx.Response(200, text="ok"),
        )
        original = ProxyEntry(
            id=1,
            method="POST",
            url="http://t.com/api",
            request_headers={"Content-Type": "application/json"},
            request_body='{"key": "val"}',
        )
        result = await replay_request(original)
        assert result.method == "POST"
        assert result.request_headers == {"Content-Type": "application/json"}
        assert result.request_body == '{"key": "val"}'

    @respx.mock
    @pytest.mark.asyncio
    async def test_modify_and_send(self):
        respx.post("http://target.com/api").mock(
            return_value=httpx.Response(201, text="created"),
        )
        original = ProxyEntry(id=3, method="GET", url="http://target.com/old")
        result = await modify_and_send(
            original,
            method="POST",
            url="http://target.com/api",
        )
        assert result.method == "POST"
        assert result.url == "http://target.com/api"
        assert result.status_code == 201
        assert "modified" in result.tags
        assert "3" in result.notes

    @respx.mock
    @pytest.mark.asyncio
    async def test_modify_keeps_original_fields_when_not_overridden(self):
        respx.get("http://target.com/page").mock(
            return_value=httpx.Response(200, text="ok"),
        )
        original = ProxyEntry(
            id=1,
            method="GET",
            url="http://target.com/page",
            request_headers={"Auth": "Bearer tok"},
        )
        result = await modify_and_send(original)
        assert result.method == "GET"
        assert result.url == "http://target.com/page"
        assert result.request_headers == {"Auth": "Bearer tok"}
