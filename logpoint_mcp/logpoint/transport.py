"""Low-level access to Logpoint's three API styles.

* Incident API: JSON body `{"username", "secret_key", "requestData": {...}}`, sent even on GET.
* Search API (`/getsearchlogs`, `/getalloweddata`): form-encoded, `requestData` is a JSON string.
* Alert Rule (Director) API: bearer JWT signed with a shared secret.
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import jwt

from ..config import LogpointSettings
from ..errors import LogpointAPIError, LogpointAuthError, LogpointError
from ..http import body_snippet, build_client, request_with_retries

_JWT_TTL_SECONDS = 3600
_JWT_REFRESH_MARGIN_SECONDS = 120


class LogpointTransport:
    def __init__(self, settings: LogpointSettings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client or build_client(
            base_url=settings.base_url,
            timeout=settings.timeout_seconds,
            verify=settings.verify,
        )
        self._jwt: str | None = None
        self._jwt_expires_at = 0.0

    async def aclose(self) -> None:
        await self._client.aclose()

    async def incident_api(
        self, method: str, endpoint: str, request_data: dict[str, Any], *, idempotent: bool
    ) -> dict[str, Any]:
        payload = {**self._credentials(), "requestData": request_data}
        response = await self._send(method, endpoint, idempotent=idempotent, json=payload)
        return self._parse(response, endpoint, require_success=True)

    async def form_api(self, endpoint: str, form: dict[str, str], *, idempotent: bool) -> dict[str, Any]:
        response = await self._send("POST", endpoint, idempotent=idempotent, data={**self._credentials(), **form})
        return self._parse(response, endpoint, require_success=True)

    async def director_api(
        self,
        method: str,
        endpoint: str,
        *,
        idempotent: bool,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._bearer_token()}"}
        response = await self._send(method, endpoint, idempotent=idempotent, params=params, json=json, headers=headers)
        return self._parse(response, endpoint, require_success=False)

    def _credentials(self) -> dict[str, str]:
        return {"username": self.settings.username, "secret_key": self.settings.secret_key.get_secret_value()}

    def _bearer_token(self) -> str:
        if not self.settings.alert_rules_enabled:
            raise LogpointError("The Alert Rule API is not configured (set LOGPOINT_JWT_SECRET and LOGPOINT_JWT_SUBJECT).")
        now = time.time()
        if self._jwt is None or self._jwt_expires_at - now < _JWT_REFRESH_MARGIN_SECONDS:
            issued_at = int(now)
            self._jwt_expires_at = issued_at + _JWT_TTL_SECONDS
            claims = {
                "sub": self.settings.jwt_subject,
                "scope": self.settings.jwt_scope,
                "iat": issued_at,
                "exp": int(self._jwt_expires_at),
                "iss": "self-signed",
            }
            secret = self.settings.jwt_secret.get_secret_value()  # type: ignore[union-attr]
            self._jwt = jwt.encode(claims, secret, algorithm=self.settings.jwt_algorithm)
        return self._jwt

    async def _send(self, method: str, endpoint: str, *, idempotent: bool, **kwargs: Any) -> httpx.Response:
        try:
            return await request_with_retries(
                self._client,
                method,
                f"/{endpoint.lstrip('/')}",
                idempotent=idempotent,
                max_retries=self.settings.max_retries,
                **kwargs,
            )
        except httpx.HTTPError as exc:
            # Never include the request in the message: its body holds the secret key.
            raise LogpointError(f"Could not reach Logpoint for /{endpoint}: {type(exc).__name__}") from None

    @staticmethod
    def _parse(response: httpx.Response, endpoint: str, *, require_success: bool) -> dict[str, Any]:
        if response.status_code in (401, 403):
            raise LogpointAuthError(
                f"Logpoint rejected the credentials for /{endpoint} (HTTP {response.status_code})."
            )
        try:
            body = response.json()
        except ValueError:
            raise LogpointAPIError(
                f"/{endpoint} returned HTTP {response.status_code} with a non-JSON body: {body_snippet(response)}"
            ) from None
        if response.is_error:
            raise LogpointAPIError(f"/{endpoint} returned HTTP {response.status_code}: {_message(body)}")
        if not isinstance(body, dict):
            raise LogpointAPIError(f"/{endpoint} returned an unexpected {type(body).__name__} instead of an object.")
        if body.get("success") is False or (require_success and body.get("success") is not True):
            raise LogpointAPIError(f"/{endpoint} failed: {_message(body)}")
        return body


def _message(body: Any) -> str:
    if isinstance(body, dict):
        for key in ("message", "error", "errors", "detail"):
            if body.get(key):
                return str(body[key])[:500]
    return str(body)[:500]
