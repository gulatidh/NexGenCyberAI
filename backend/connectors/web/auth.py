"""Pre-login flow for the web (ZAP) connector.

For form-based and OAuth client-credentials auth, the backend logs in
*before* triggering the GitHub workflow and passes the resulting header
to ZAP. This keeps the workflow simple (no ZAP scripting) and avoids
echoing creds into workflow inputs.

`prepare_auth_headers(auth)` returns a dict of header name → value that
ZAP should inject on every request, e.g. {"Authorization": "Bearer ..."}.
"""
from __future__ import annotations
import logging
from typing import Dict, Any

import httpx

logger = logging.getLogger(__name__)


def prepare_auth_headers(auth: Dict[str, Any]) -> Dict[str, str]:
    """Build the headers ZAP should inject given a connector auth config.

    Returns an empty dict for `none` or on any failure (the scan still
    proceeds unauthenticated rather than blocking).
    """
    method = (auth or {}).get("method", "none").lower()
    if method == "none" or not auth:
        return {}

    if method == "bearer":
        token = (auth.get("token") or "").strip()
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

    if method == "cookie":
        name = (auth.get("cookie_name") or "").strip()
        value = (auth.get("cookie_value") or "").strip()
        if not name or not value:
            return {}
        return {"Cookie": f"{name}={value}"}

    if method == "form":
        return _form_login(auth)

    if method in ("oauth_client_credentials", "oauth_cc"):
        return _oauth_client_credentials(auth)

    logger.warning("Unknown web auth method %r — proceeding unauth", method)
    return {}


def _form_login(auth: Dict[str, Any]) -> Dict[str, str]:
    """Submit a form login and capture the resulting session cookie.

    Required fields: login_url, username, password, username_field, password_field.
    """
    login_url = auth.get("login_url")
    username = auth.get("username")
    password = auth.get("password")
    u_field = auth.get("username_field") or "username"
    p_field = auth.get("password_field") or "password"
    if not (login_url and username and password):
        return {}

    try:
        with httpx.Client(timeout=20, follow_redirects=False) as client:
            resp = client.post(login_url, data={u_field: username, p_field: password})
            # Common patterns: 200 with Set-Cookie, or 302 redirect with Set-Cookie.
            cookies = resp.cookies
            if not cookies:
                logger.warning("Form login returned no cookies (status %s)", resp.status_code)
                return {}
            cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
            return {"Cookie": cookie_header}
    except Exception as exc:
        logger.warning("Form login failed: %s", exc)
        return {}


def _oauth_client_credentials(auth: Dict[str, Any]) -> Dict[str, str]:
    """OAuth 2.0 client_credentials grant. Returns Bearer header."""
    token_url = auth.get("token_url")
    client_id = auth.get("client_id")
    client_secret = auth.get("client_secret")
    scope = auth.get("scope")
    if not (token_url and client_id and client_secret):
        return {}

    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    if scope:
        data["scope"] = scope
    try:
        with httpx.Client(timeout=20) as client:
            resp = client.post(token_url, data=data)
            resp.raise_for_status()
            payload = resp.json()
            token = payload.get("access_token")
            if not token:
                logger.warning("OAuth token response missing access_token")
                return {}
            return {"Authorization": f"Bearer {token}"}
    except Exception as exc:
        logger.warning("OAuth client_credentials failed: %s", exc)
        return {}
