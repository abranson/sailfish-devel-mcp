"""Parse OBS source pins without reformatting or exposing other service parameters."""

from __future__ import annotations

import hashlib
from xml.parsers import expat
from xml.sax.saxutils import escape


def service_sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _tag_end(source: bytes, start: int) -> int:
    quote = None
    for index in range(start, len(source)):
        char = source[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in (34, 39):
            quote = char
        elif char == 62:
            return index + 1
    raise ValueError("unterminated XML tag")


def source_pins(source: str) -> list[dict]:
    """Return pin values and byte spans; keep comments and unrelated XML intact."""
    data = source.encode("utf-8")
    parser = expat.ParserCreate("UTF-8")
    stack = []
    services = []

    def start(name, attrs):
        if not stack and name != "services":
            raise ValueError("_service must have a services root")
        node = {"tag": name, "attrs": attrs, "text": [], "children": False,
                "start": _tag_end(data, parser.CurrentByteIndex)}
        if stack:
            stack[-1]["children"] = True
        if len(stack) == 1 and name == "service":
            node["params"] = {}
            node["service_index"] = len(services)
            services.append(node)
        stack.append(node)

    def end(name):
        node = stack.pop()
        if len(stack) == 2 and stack[-1]["tag"] == "service" and name == "param":
            key = node["attrs"].get("name")
            if key in ("url", "branch", "revision"):
                params = stack[-1]["params"]
                if key in params:
                    raise ValueError(f"duplicate {key} parameter in source service")
                if node["children"]:
                    raise ValueError(f"nested XML in {key} parameter")
                params[key] = {"value": "".join(node["text"]),
                               "span": (node["start"], parser.CurrentByteIndex)}

    def reject_doctype(*args):
        raise ValueError("DOCTYPE is not supported in _service")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = lambda text: stack[-1]["text"].append(text) if stack else None
    parser.StartDoctypeDeclHandler = reject_doctype
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ValueError(f"invalid _service XML: {exc}") from exc
    return [{"service_index": service["service_index"],
             "service": service["attrs"].get("name", ""),
             "params": service["params"]}
            for service in services if "revision" in service["params"]]


def public_pin(pin: dict) -> dict:
    return {"service_index": pin["service_index"], "service": pin["service"],
            **{name: param["value"] for name, param in pin["params"].items()}}


def edit_source_pin(source: str, pins: list[dict], service_index: int | None,
                    revision: str, branch: str | None) -> tuple[str, dict]:
    matches = [pin for pin in pins if service_index is None or pin["service_index"] == service_index]
    if len(matches) != 1:
        raise ValueError("select exactly one source pin using service_index from read")
    pin = matches[0]
    replacements = []
    changes = {}
    data = source.encode("utf-8")
    for name, value in (("revision", revision), ("branch", branch)):
        if value is None:
            continue
        if not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(f"{name} must be non-empty text without control characters")
        param = pin["params"].get(name)
        if param is None:
            raise ValueError(f"selected source service has no existing {name} parameter")
        start, end = param["span"]
        if not param["value"].strip() or end < start or b"<" in data[start:end]:
            raise ValueError(f"{name} must contain plain, non-empty XML text")
        if value != param["value"]:
            replacements.append((start, end, escape(value).encode("utf-8")))
            changes[name] = {"before": param["value"], "after": value}
    for start, end, value in sorted(replacements, reverse=True):
        data = data[:start] + value + data[end:]
    updated = data.decode("utf-8")
    source_pins(updated)
    return updated, {"service_index": pin["service_index"], "service": pin["service"],
                     "changes": changes}
