from __future__ import annotations

from jarvis.llm.ollama_client import _normalize_arguments


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
