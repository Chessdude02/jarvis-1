from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from jarvis.llm.ollama_client import OllamaClient, OllamaUnavailableError, _normalize_arguments


def test_dict_arguments_pass_through():
    assert _normalize_arguments({"path": "/tmp"}) == {"path": "/tmp"}


def test_json_string_arguments_are_parsed():
    assert _normalize_arguments('{"path": "/tmp"}') == {"path": "/tmp"}


def test_none_arguments_become_empty_dict():
    assert _normalize_arguments(None) == {}


def test_garbage_string_arguments_become_empty_dict():
    assert _normalize_arguments("not json at all") == {}


def test_non_object_json_becomes_empty_dict():
    # A model that returns a JSON array or scalar for "arguments" instead of
    # an object must not propagate that shape downstream.
    assert _normalize_arguments("[1, 2, 3]") == {}
    assert _normalize_arguments([1, 2, 3]) == {}
    assert _normalize_arguments("42") == {}
    assert _normalize_arguments(42) == {}


def _client_with_fake_response(settings, body):
    client = OllamaClient(settings)
    fake_resp = MagicMock()
    fake_resp.raise_for_status = lambda: None
    fake_resp.json = lambda: body
    patcher = patch("requests.post", return_value=fake_resp)
    return client, patcher


def test_malformed_response_bare_array_raises_ollama_unavailable(settings):
    # A 200 OK response is not a guarantee of a well-shaped body -- found by
    # testing: something other than Ollama answering on the configured port
    # (or a bug in Ollama itself) previously crashed with an uncaught
    # AttributeError ('list' object has no attribute 'get') instead of the
    # OllamaUnavailableError the orchestrator already knows how to report.
    client, patcher = _client_with_fake_response(settings, [1, 2, 3])
    with patcher:
        with pytest.raises(OllamaUnavailableError):
            client.chat([{"role": "user", "content": "hi"}])


def test_malformed_response_bare_string_raises_ollama_unavailable(settings):
    client, patcher = _client_with_fake_response(settings, "not an object")
    with patcher:
        with pytest.raises(OllamaUnavailableError):
            client.chat([{"role": "user", "content": "hi"}])


def test_malformed_response_message_wrong_type_raises_ollama_unavailable(settings):
    client, patcher = _client_with_fake_response(settings, {"message": "oops, a string"})
    with patcher:
        with pytest.raises(OllamaUnavailableError):
            client.chat([{"role": "user", "content": "hi"}])


def test_missing_message_field_does_not_crash(settings):
    client, patcher = _client_with_fake_response(settings, {})
    with patcher:
        result = client.chat([{"role": "user", "content": "hi"}])
    assert result.content == ""
    assert result.tool_calls == []


def test_garbage_tool_call_entries_are_skipped_not_crashed_on(settings):
    client, patcher = _client_with_fake_response(settings, {"message": {"tool_calls": ["not", "a", "dict", 123, None], "content": "hi"}})
    with patcher:
        result = client.chat([{"role": "user", "content": "hi"}])
    assert result.content == "hi"
    assert result.tool_calls == []


def test_well_formed_response_still_works(settings):
    client, patcher = _client_with_fake_response(settings, {
        "message": {"content": "hello", "tool_calls": [{"id": "1", "function": {"name": "get_memory_usage", "arguments": {}}}]},
    })
    with patcher:
        result = client.chat([{"role": "user", "content": "hi"}])
    assert result.content == "hello"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "get_memory_usage"
