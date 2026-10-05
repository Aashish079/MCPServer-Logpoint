"""Command line entry point: `logpoint-mcp` or `python -m logpoint_mcp`."""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from pydantic import ValidationError

from . import __version__, config
from .config import Settings
from .logging_setup import configure_logging
from .server import create_server
from .services import Services

logger = logging.getLogger("logpoint_mcp")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="logpoint-mcp", description="MCP server for the Logpoint SIEM")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio",
                        help="stdio for local clients (Claude Desktop/Code); http for remote clients (streamable HTTP)")
    parser.add_argument("--host", help="HTTP bind address (overrides MCP_HOST)")
    parser.add_argument("--port", type=int, help="HTTP port (overrides MCP_PORT)")
    parser.add_argument("--check", action="store_true", help="Validate configuration and Logpoint access, then exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        settings = Settings.load()
    except ValidationError as exc:
        print(_describe_config_error(exc), file=sys.stderr)
        return 2
    if args.host:
        settings.server.host = args.host
    if args.port:
        settings.server.port = args.port
    configure_logging(settings.server)

    if args.check:
        return asyncio.run(_check(settings))
    if args.transport == "stdio":
        asyncio.run(_run_stdio(settings))
        return 0
    return _run_http(settings)


async def _run_stdio(settings: Settings) -> None:
    services = Services.from_settings(settings)
    _log_startup(settings, services, "stdio")
    try:
        await create_server(settings, services).run_stdio_async()
    finally:
        await services.aclose()


def _run_http(settings: Settings) -> int:
    import uvicorn

    from .http_app import create_http_app

    services = Services.from_settings(settings)
    try:
        app = create_http_app(settings, services, create_server(settings, services))
    except ValueError as exc:
        logger.error("%s", exc)
        return 2
    _log_startup(settings, services, f"http://{settings.server.host}:{settings.server.port}{settings.server.path}")
    uvicorn.run(app, host=settings.server.host, port=settings.server.port, log_config=None,
                proxy_headers=True, server_header=False)
    return 0


async def _check(settings: Settings) -> int:
    services = Services.from_settings(settings)
    try:
        await services.search.allowed_data("user_preference")
        repos = await services.search.list_repos()
        users = await services.incidents.list_users()
        await services.incidents.api_user_id()
        print(f"Logpoint OK: {len(repos)} repos, {len(users)} users, API user found in get_users")
        print(f"Write actions: {'enabled' if settings.server.allow_write_actions else 'disabled'}")
        print("Integrations: " + ", ".join(f"{k}={'on' if v else 'off'}" for k, v in services.describe().items()))
        return 0
    except Exception as exc:
        print(f"Check failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        await services.aclose()


def _log_startup(settings: Settings, services: Services, where: str) -> None:
    enabled = [name for name, on in services.describe().items() if on]
    logger.info(
        "logpoint-mcp %s serving on %s (Logpoint %s, write actions %s, integrations: %s)",
        __version__, where, settings.logpoint.base_url,
        "ENABLED" if settings.server.allow_write_actions else "disabled",
        ", ".join(enabled) or "none",
    )


def _describe_config_error(exc: ValidationError) -> str:
    """Name the environment variables at fault (never their values)."""
    model = getattr(config, exc.title, None)
    prefix = model.model_config.get("env_prefix", "") if model is not None else ""
    lines = ["Invalid configuration:"]
    for error in exc.errors():
        field = ".".join(str(part) for part in error["loc"])
        lines.append(f"  {prefix}{field.upper()}: {error['msg']}")
    lines.append("Set these in the environment or in a .env file (see .env.example).")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
