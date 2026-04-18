from vapt_orchestrator_safe.utils.llm_json import extract_json


def test_returns_none_for_empty():
    assert extract_json("") is None
    assert extract_json("   ") is None


def test_pure_json_object():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_pure_json_array():
    assert extract_json("[1, 2, 3]") == [1, 2, 3]


def test_strips_markdown_fence():
    text = "Here is the JSON:\n```json\n{\"a\": 1, \"b\": [2,3]}\n```\nThanks!"
    assert extract_json(text) == {"a": 1, "b": [2, 3]}


def test_strips_unlabeled_fence():
    text = "```\n{\"x\": true}\n```"
    assert extract_json(text) == {"x": True}


def test_brace_match_with_prose_around():
    text = "Sure! Here you go: {\"k\": \"v\"} — let me know if you need more."
    assert extract_json(text) == {"k": "v"}


def test_brace_match_handles_nested_braces():
    text = 'noise {"outer": {"inner": [1, 2, {"deep": true}]}, "tail": 0} more noise'
    parsed = extract_json(text)
    assert parsed == {"outer": {"inner": [1, 2, {"deep": True}]}, "tail": 0}


def test_brace_match_handles_braces_inside_strings():
    text = 'prefix {"q": "a } b { c", "n": 1} suffix'
    assert extract_json(text) == {"q": "a } b { c", "n": 1}


def test_returns_none_for_unclosed_json():
    assert extract_json('{"a": 1, "b": [') is None


def test_thinking_tokens_before_json():
    # Simulates a thinking-mode model that dumps reasoning then JSON.
    text = (
        "<think>Let me analyze the input. The user wants endpoints...</think>\n"
        '{"endpoints": [], "auth_surface": "none", "stack_fingerprint": "x", '
        '"suspicious_patterns": [], "next_recon_actions": []}'
    )
    parsed = extract_json(text)
    assert parsed is not None
    assert parsed["auth_surface"] == "none"
    assert parsed["endpoints"] == []
