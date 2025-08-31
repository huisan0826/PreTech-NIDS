import http.server
import socketserver
import threading
import urllib.parse
import webbrowser
import time
import sys
import os
import json
from typing import Optional

import requests


class OAuthCodeCatcher:
    def __init__(self, port: int = 53682):
        self.port = port
        self.code: Optional[str] = None
        self.state: Optional[str] = None
        self._server = None
        self._thread = None

    def start(self):
        handler_self = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != "/callback":
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not Found")
                    return
                qs = urllib.parse.parse_qs(parsed.query)
                handler_self.code = qs.get("code", [None])[0]
                handler_self.state = qs.get("state", [None])[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><body><h2>Authorization received.</h2><p>You can close this tab and return to the app.</p></body></html>")

            def log_message(self, format, *args):
                return

        self._server = socketserver.TCPServer(("localhost", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass


def build_google_auth_url(client_id: str, redirect_uri: str, scope: str, state: str = "state") -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


def exchange_google_token(client_id: str, client_secret: str, code: str, redirect_uri: str, token_uri: str = "https://oauth2.googleapis.com/token") -> dict:
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    resp = requests.post(token_uri, data=data, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"Google token exchange failed: {resp.status_code} {resp.text}")
    return resp.json()


def build_ms_auth_url(client_id: str, redirect_uri: str, scope: str, tenant: str = "common", state: str = "state") -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "response_mode": "query",
        "state": state,
    }
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?" + urllib.parse.urlencode(params)


def exchange_ms_token(client_id: str, client_secret: str, code: str, redirect_uri: str, tenant: str = "common") -> dict:
    token_uri = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    resp = requests.post(token_uri, data=data, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"Microsoft token exchange failed: {resp.status_code} {resp.text}")
    return resp.json()


def write_env_updates(env_path: str, updates: dict):
    existing = {}
    try:
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip() or line.strip().startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.rstrip("\n").split("=", 1)
                        existing[k] = v
    except Exception:
        pass

    existing.update(updates)
    lines = [f"{k}={v}" for k, v in existing.items()]
    with open(env_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Obtain OAuth2 refresh token for Gmail or Microsoft and optionally write to .env")
    parser.add_argument("--provider", choices=["google", "microsoft"], required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", required=True)
    parser.add_argument("--scope", default="")
    parser.add_argument("--tenant", default="common")
    parser.add_argument("--env", dest="env_path", default=os.path.join(os.path.dirname(__file__), "..", ".env"))
    parser.add_argument("--write-env", action="store_true")
    args = parser.parse_args()

    port = 53682
    redirect_uri = f"http://localhost:{port}/callback"

    catcher = OAuthCodeCatcher(port)
    catcher.start()
    try:
        if args.provider == "google":
            scope = args.scope or "https://mail.google.com/"
            auth_url = build_google_auth_url(args.client_id, redirect_uri, scope)
        else:
            scope = args.scope or "https://outlook.office365.com/.default offline_access"
            auth_url = build_ms_auth_url(args.client_id, redirect_uri, scope, tenant=args.tenant)

        webbrowser.open(auth_url)
        print(f"Open this URL if the browser didn't launch:\n{auth_url}\n")

        start = time.time()
        while catcher.code is None and time.time() - start < 300:
            time.sleep(0.5)
        if catcher.code is None:
            raise RuntimeError("Timed out waiting for authorization code")

        if args.provider == "google":
            token_data = exchange_google_token(args.client_id, args.client_secret, catcher.code, redirect_uri)
        else:
            token_data = exchange_ms_token(args.client_id, args.client_secret, catcher.code, redirect_uri, tenant=args.tenant)

        refresh_token = token_data.get("refresh_token")
        if not refresh_token:
            raise RuntimeError("No refresh_token returned. Ensure offline access/consent is requested.")

        print("\nCopy these into your .env:")
        updates = {
            "SMTP_AUTH_METHOD": "OAUTH2",
            "OAUTH_CLIENT_ID": args.client_id,
            "OAUTH_CLIENT_SECRET": args.client_secret,
            "OAUTH_REFRESH_TOKEN": refresh_token,
        }
        if args.provider == "google":
            print("OAUTH_PROVIDER=GOOGLE")
            print("OAUTH_TOKEN_URI=https://oauth2.googleapis.com/token")
            print("OAUTH_SCOPE=https://mail.google.com/")
            updates.update({
                "OAUTH_PROVIDER": "GOOGLE",
                "OAUTH_TOKEN_URI": "https://oauth2.googleapis.com/token",
                "OAUTH_SCOPE": "https://mail.google.com/",
            })
        else:
            print("OAUTH_PROVIDER=MICROSOFT")
            print("OAUTH_TENANT=common")
            print("OAUTH_SCOPE=https://outlook.office365.com/.default offline_access")
            updates.update({
                "OAUTH_PROVIDER": "MICROSOFT",
                "OAUTH_TENANT": args.tenant,
                "OAUTH_SCOPE": "https://outlook.office365.com/.default offline_access",
            })

        if args.write_env:
            env_path = os.path.abspath(args.env_path)
            write_env_updates(env_path, updates)
            print(f"\nUpdated .env at: {env_path}")
    finally:
        catcher.stop()


if __name__ == "__main__":
    main()


