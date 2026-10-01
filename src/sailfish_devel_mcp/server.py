from __future__ import annotations

import argparse
from datetime import datetime
import json
import sys
import time
from typing import Any, TextIO

from . import __version__
from .config import Config, load_config
from .tools import MAX_MCP_WAIT_SECONDS, build_registry, tool_error


PROTOCOL_VERSIONS = [
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
]
SERVER_NAME = "sailfish-devel-mcp"


def _log_value(value: Any, max_length: int = 200) -> str:
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def _log_line(message: str) -> None:
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"[{timestamp}] {SERVER_NAME} {message}", file=sys.stderr, flush=True)


def _duration_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Any | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class McpServer:
    def __init__(self, config: Config):
        self.config = config
        self.registry = build_registry(config)

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            _log_line("mcp request rejected reason=non_object")
            raise JsonRpcError(-32600, "JSON-RPC message must be an object")

        request_id = message.get("id")
        method = message.get("method")
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str) or not method:
            _log_line(f"mcp request rejected id={_log_value(request_id)} reason=missing_method")
            raise JsonRpcError(-32600, "JSON-RPC message is missing method")

        if request_id is None:
            _log_line(f"mcp notification method={_log_value(method)}")
            self._handle_notification(method)
            return None

        started = time.monotonic()
        _log_line(f"mcp request start id={_log_value(request_id)} method={_log_value(method)}")
        try:
            result = self._dispatch(method, message.get("params") or {})
            _log_line(
                "mcp request finish "
                f"id={_log_value(request_id)} method={_log_value(method)} "
                f"status=ok duration_ms={_duration_ms(started)}"
            )
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except JsonRpcError as exc:
            _log_line(
                "mcp request finish "
                f"id={_log_value(request_id)} method={_log_value(method)} "
                f"status=jsonrpc_error code={exc.code} duration_ms={_duration_ms(started)}"
            )
            error: dict[str, Any] = {"code": exc.code, "message": exc.message}
            if exc.data is not None:
                error["data"] = exc.data
            return {"jsonrpc": "2.0", "id": request_id, "error": error}
        except Exception as exc:  # pragma: no cover - defensive protocol boundary
            _log_line(
                "mcp request finish "
                f"id={_log_value(request_id)} method={_log_value(method)} "
                f"status=exception exception={type(exc).__name__} "
                f"duration_ms={_duration_ms(started)}"
            )
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": str(exc)},
            }

    def _handle_notification(self, method: str) -> None:
        if method in {"notifications/initialized", "notifications/cancelled"}:
            return

    def _dispatch(self, method: str, params: Any) -> dict[str, Any]:
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [tool.spec for tool in self.registry.values()]}
        if method == "tools/call":
            return self._call_tool(params)
        if method == "resources/list":
            return self._resources_list()
        if method == "resources/read":
            return self._resources_read(params)
        if method == "prompts/list":
            return {"prompts": []}
        if method == "logging/setLevel":
            return {}
        raise JsonRpcError(-32601, f"method not found: {method}")

    def _initialize(self, params: Any) -> dict[str, Any]:
        requested = ""
        client_name = ""
        client_version = ""
        if isinstance(params, dict):
            requested = str(params.get("protocolVersion") or "")
            client_info = params.get("clientInfo")
            if isinstance(client_info, dict):
                client_name = str(client_info.get("name") or "")
                client_version = str(client_info.get("version") or "")
        protocol = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        _log_line(
            "mcp initialize "
            f"client={_log_value(client_name or 'unknown')} "
            f"client_version={_log_value(client_version or 'unknown')} "
            f"requested_protocol={_log_value(requested or 'unspecified')} "
            f"selected_protocol={protocol}"
        )
        return {
            "protocolVersion": protocol,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": __version__,
            },
            "instructions": "Use detached jobs for long work; keep routine status output compact.",
        }

    def _call_tool(self, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise JsonRpcError(-32602, "tools/call params must be an object")
        name = params.get("name")
        if not isinstance(name, str):
            raise JsonRpcError(-32602, "tools/call requires a tool name")
        if name not in self.registry:
            raise JsonRpcError(-32602, f"unknown tool: {name}")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            _log_line(f"mcp tool call rejected tool={_log_value(name)} reason=arguments_not_object")
            return tool_error("tool arguments must be an object")
        arg_keys = ",".join(sorted(str(key) for key in args.keys())) or "-"
        started = time.monotonic()
        _log_line(f"mcp tool call start tool={_log_value(name)} arg_keys={_log_value(arg_keys)}")
        try:
            result = self.registry[name].handler(args)
            is_error = bool(result.get("isError")) if isinstance(result, dict) else False
            _log_line(
                "mcp tool call finish "
                f"tool={_log_value(name)} is_error={str(is_error).lower()} "
                f"duration_ms={_duration_ms(started)}"
            )
            return result
        except ValueError as exc:
            _log_line(
                "mcp tool call finish "
                f"tool={_log_value(name)} is_error=true exception=ValueError "
                f"duration_ms={_duration_ms(started)}"
            )
            return tool_error(str(exc))
        except Exception as exc:
            _log_line(
                "mcp tool call finish "
                f"tool={_log_value(name)} is_error=true exception={type(exc).__name__} "
                f"duration_ms={_duration_ms(started)}"
            )
            return tool_error(
                f"{name} failed: {exc}",
                {
                    "error": str(exc),
                    "exception": type(exc).__name__,
                    "tool": name,
                },
            )

    def _resources_list(self) -> dict[str, Any]:
        return {
            "resources": [
                {
                    "uri": "sailfish-devel-mcp://config/effective",
                    "name": "Effective configuration",
                    "mimeType": "application/json",
                    "description": "Resolved configuration including private host identifiers and local paths; credential files are not read.",
                },
                {
                    "uri": "sailfish-devel-mcp://help/tools",
                    "name": "Tool summary",
                    "mimeType": "text/plain",
                    "description": "Names and descriptions of exposed tools.",
                },
            ]
        }

    def _resources_read(self, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict) or not isinstance(params.get("uri"), str):
            raise JsonRpcError(-32602, "resources/read requires a uri")
        uri = params["uri"]
        if uri == "sailfish-devel-mcp://config/effective":
            text = json.dumps(self.config.public_dict(), indent=2, sort_keys=True)
            return {"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]}
        if uri == "sailfish-devel-mcp://help/tools":
            text = "\n".join(
                f"{tool.spec['name']}: {tool.spec.get('description', '')}"
                for tool in self.registry.values()
            )
            return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": text}]}
        raise JsonRpcError(-32602, f"unknown resource: {uri}")


def run_stdio(server: McpServer, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
    for line in stdin:
        if not line.strip():
            continue
        message: Any = None
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"parse error: {exc}"},
            }
        else:
            try:
                response = server.handle(message)
            except JsonRpcError as exc:
                request_id = message.get("id") if isinstance(message, dict) else None
                if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
                    request_id = None
                response = {"jsonrpc": "2.0", "id": request_id,
                            "error": {"code": exc.code, "message": exc.message}}
        if response is not None:
            try:
                response_text = json.dumps(response, separators=(",", ":"))
            except TypeError as exc:
                request_id = message.get("id") if isinstance(message, dict) else None
                response_text = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32603,
                            "message": f"response serialization failed: {exc}",
                        },
                    },
                    separators=(",", ":"),
                )
            try:
                stdout.write(response_text + "\n")
                stdout.flush()
            except BrokenPipeError:
                return


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Sailfish OS development MCP server")
    parser.add_argument("--config", help="Path to config.json")
    parser.add_argument(
        "--dump-config",
        action="store_true",
        help="Print the resolved config and exit",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)
    if args.dump_config:
        print(json.dumps(config.public_dict(), indent=2, sort_keys=True))
        return

    _log_line(f"mcp server ready name={SERVER_NAME} version={__version__}")
    run_stdio(McpServer(config))


if __name__ == "__main__":
    main()
