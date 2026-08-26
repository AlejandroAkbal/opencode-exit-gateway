import base64
import concurrent.futures
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = int(os.environ.get("MAX_BODY", 16 * 1024 * 1024))
PEEK_BYTES = int(os.environ.get("PEEK_BYTES", 64 * 1024))
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", 8))
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", 180))
REFRESH_SECONDS = int(os.environ.get("REFRESH_SECONDS", 1200))
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", 1800))
ELIGIBLE = {403, 429, 503}
CHALLENGE = re.compile(rb"captcha|cf-chl|challenge-platform|unusual traffic|temporarily blocked", re.I)
HOP_HEADERS = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer"}


@dataclass(frozen=True)
class Proxy:
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""
    latency: float = 9999.0

    @property
    def key(self):
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def label(self):
        return hashlib.sha256(self.key.encode()).hexdigest()[:10]


class StickyPool:
    def __init__(self, proxies=()):
        self._lock = threading.Lock()
        self._proxies = list(proxies)
        self._active = self._proxies[0] if self._proxies else None
        self._cooldown = {}

    def current(self):
        with self._lock:
            return self._active

    def count(self):
        with self._lock:
            return len(self._proxies)

    def reconcile(self, fresh):
        now = time.time()
        by_key = {p.key: p for p in fresh if self._cooldown.get(p.key, 0) <= now}
        ranked = sorted(by_key.values(), key=lambda p: p.latency)
        with self._lock:
            # ponytail: feed churn never moves a working active exit; request failure owns rotation.
            if self._active and self._cooldown.get(self._active.key, 0) <= now:
                by_key[self._active.key] = self._active
                ranked = [self._active] + [p for p in ranked if p.key != self._active.key]
            self._proxies = ranked
            if not self._active or self._active.key not in {p.key for p in ranked}:
                self._active = ranked[0] if ranked else None

    def fail(self, failed):
        now = time.time()
        with self._lock:
            self._cooldown[failed.key] = now + COOLDOWN_SECONDS
            self._proxies = [p for p in self._proxies if p.key != failed.key]
            if self._active and self._active.key == failed.key:
                self._active = self._proxies[0] if self._proxies else None
            return self._active


class BeforeSendError(Exception):
    pass


class AfterSendError(Exception):
    pass


def filter_free_models(catalog):
    return {**catalog, "data": [model for model in catalog.get("data", []) if str(model.get("id", "")).endswith("-free")]}


def _read_head(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk or len(data) >= 16384:
            raise BeforeSendError("invalid proxy CONNECT response")
        data += chunk
    return bytes(data)


def _proxy_socket(proxy, host, port):
    raw = socket.create_connection((proxy.host, proxy.port), CONNECT_TIMEOUT)
    raw.settimeout(UPSTREAM_TIMEOUT)
    if proxy.scheme == "https":
        raw = ssl.create_default_context().wrap_socket(raw, server_hostname=proxy.host)
    auth = ""
    if proxy.username:
        token = base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
        auth = f"Proxy-Authorization: Basic {token}\r\n"
    raw.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n".encode())
    status = _read_head(raw).split(b"\r\n", 1)[0].split()
    if len(status) < 2 or status[1] != b"200":
        raw.close()
        raise BeforeSendError("proxy CONNECT rejected")
    return raw


def request_via(proxy, method, host, port, path, headers, body=b"", use_tls=True):
    sock = None
    sent = False
    try:
        sock = _proxy_socket(proxy, host, port)
        if use_tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        lines.extend(f"{k}: {v}" for k, v in headers.items() if k.lower() not in HOP_HEADERS and k.lower() != "host")
        lines.extend(["Connection: close", "", ""])
        sent = True
        sock.sendall("\r\n".join(lines).encode() + body)
        response = http.client.HTTPResponse(sock)
        response.begin()
        return response, sock
    except Exception as exc:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        if isinstance(exc, (BeforeSendError, AfterSendError)):
            raise
        raise (AfterSendError if sent else BeforeSendError)(str(exc)) from exc


def _parse_feed(text):
    proxies = []
    current = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("- name:"):
            if current.get("server") and current.get("port"):
                proxies.append(current)
            current = {}
        elif line.startswith("type:"):
            current["type"] = line.split(":", 1)[1].strip()
        elif line.startswith("server:"):
            value = line.split(":", 1)[1].strip()
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
            current["server"] = str(value)
        elif line.startswith("port:"):
            try:
                current["port"] = int(line.split(":", 1)[1])
            except ValueError:
                pass
    if current.get("server") and current.get("port"):
        proxies.append(current)
    return [Proxy("http", p["server"], p["port"]) for p in proxies if p.get("type") == "http"]


class Gateway:
    def __init__(self, pool, api_key, upstream_host="opencode.ai", upstream_port=443, upstream_tls=True, retries=2):
        self.pool = pool
        self.api_key = api_key
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_tls = upstream_tls
        self.retries = retries

    def authorized(self, value):
        expected = f"Bearer {self.api_key}"
        return bool(self.api_key) and hmac.compare_digest(value or "", expected)

    def upstream_headers(self, body_length, accept):
        return {
            "Authorization": "Bearer public",
            "Content-Type": "application/json",
            "Content-Length": str(body_length),
            "Accept": accept,
            "User-Agent": "opencode",
            "x-opencode-client": "desktop",
            "x-opencode-session": f"ses_{uuid.uuid4().hex}",
            "x-opencode-request": f"msg_{uuid.uuid4().hex}",
            "x-opencode-project": "global",
        }

    def perform(self, method, path, body=b"", accept="*/*", host=None, port=None, headers_override=None, use_ssl=None):
        if host is None:
            host = self.upstream_host
        if port is None:
            port = self.upstream_port
        if use_ssl is None:
            use_ssl = self.upstream_tls
        if headers_override is not None:
            headers = headers_override
        else:
            headers = self.upstream_headers(len(body), accept)
        last = None
        for attempt in range(self.retries + 1):
            proxy = self.pool.current()
            if not proxy:
                raise BeforeSendError("no healthy exits")
            try:
                response, sock = request_via(proxy, method, host, port, path, headers, body, use_ssl)
                prefix = response.read1(PEEK_BYTES) if hasattr(response, "read1") else response.read(PEEK_BYTES)
                blocked = response.status in ELIGIBLE or CHALLENGE.search(prefix)
                if blocked and attempt < self.retries:
                    response.close()
                    sock.close()
                    self.pool.fail(proxy)
                    last = (response.status, prefix)
                    continue
                return response, sock, prefix
            except BeforeSendError:
                self.pool.fail(proxy)
                if attempt >= self.retries:
                    raise
            except AfterSendError:
                self.pool.fail(proxy)
                raise
        raise BeforeSendError(f"exits exhausted: {last[0] if last else 'network'}")

    def refresh(self, adapter_url):
        feeds = ("worldpool", "proxifly", "monosans", "relayglass-https", "gproxy-http", "aliilapro")
        candidates = {}
        for feed in feeds:
            try:
                with urllib.request.urlopen(f"{adapter_url.rstrip('/')}/{feed}.yaml", timeout=10) as response:
                    for proxy in _parse_feed(response.read().decode("utf-8", "replace")):
                        candidates[proxy.key] = proxy
            except Exception:
                continue

        def validate(proxy):
            start = time.monotonic()
            response = sock = None
            try:
                response, sock = request_via(proxy, "GET", self.upstream_host, self.upstream_port, "/zen/v1/models", {
                    "Authorization": "Bearer public", "Accept": "application/json", "User-Agent": "opencode", "x-opencode-client": "desktop"
                }, use_tls=self.upstream_tls)
                response.read(1)
                return Proxy(proxy.scheme, proxy.host, proxy.port, proxy.username, proxy.password, time.monotonic() - start) if response.status == 200 else None
            except Exception:
                return None
            finally:
                if response:
                    response.close()
                if sock:
                    sock.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as workers:
            healthy = [p for p in workers.map(validate, candidates.values()) if p]
        self.pool.reconcile(healthy)
        return len(candidates), len(healthy)


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _json(self, status, payload):
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _auth(self):
            if app.authorized(self.headers.get("Authorization")):
                return True
            self._json(401, {"error": {"message": "unauthorized", "type": "authentication_error"}})
            return False

        def _relay(self, response, sock, prefix):
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in HOP_HEADERS | {"content-length"}:
                    self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            if prefix:
                self.wfile.write(prefix)
                self.wfile.flush()
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
            response.close()
            sock.close()
            self.close_connection = True

        def _relay_dynamic(self, method):
            if not self._auth():
                return
            target_url = self.headers.get("x-target-url")
            if not target_url:
                return self._json(400, {"error": {"message": "x-target-url header required for generic REST relay"}})
            parsed = urllib.parse.urlparse(target_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                return self._json(400, {"error": {"message": "invalid x-target-url scheme or host"}})
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_ssl = (parsed.scheme == "https")
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._json(400, {"error": {"message": "invalid content length"}})
            if length > MAX_BODY:
                return self._json(413, {"error": {"message": "request body rejected"}})
            body = self.rfile.read(length) if length > 0 else b""

            headers = {}
            for k, v in self.headers.items():
                if k.lower() not in ("host", "authorization", "content-length", "x-target-url", "connection"):
                    headers[k] = v
            headers["Host"] = parsed.netloc
            headers["Content-Length"] = str(len(body))

            try:
                response, sock, prefix = app.perform(
                    method, path, body,
                    host=host, port=port, headers_override=headers, use_ssl=use_ssl
                )
                return self._relay(response, sock, prefix)
            except AfterSendError:
                return self._json(502, {"error": {"message": "ambiguous upstream failure; request not replayed"}})
            except Exception:
                return self._json(503, {"error": {"message": "no healthy upstream exit"}})

        def do_GET(self):
            if self.path == "/health":
                return self._json(200 if app.pool.current() else 503, {"status": "ok" if app.pool.current() else "no_exits", "exits": app.pool.count()})
            if self.headers.get("x-target-url"):
                return self._relay_dynamic("GET")
            if self.path != "/v1/models":
                return self._json(404, {"error": {"message": "not found"}})
            if not self._auth():
                return
            try:
                response, sock, prefix = app.perform("GET", "/zen/v1/models", accept="application/json")
                try:
                    if response.status != 200:
                        return self._relay(response, sock, prefix)
                    return self._json(200, filter_free_models(json.loads(prefix + response.read())))
                finally:
                    response.close()
                    sock.close()
            except Exception:
                return self._json(503, {"error": {"message": "no healthy upstream exit"}})

        def do_POST(self):
            if self.headers.get("x-target-url"):
                return self._relay_dynamic("POST")
            if self.path != "/v1/chat/completions":
                return self._json(404, {"error": {"message": "not found"}})
            if not self._auth():
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._json(400, {"error": {"message": "invalid content length"}})
            if length <= 0 or length > MAX_BODY:
                return self._json(413, {"error": {"message": "request body rejected"}})
            body = self.rfile.read(length)
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                return self._json(400, {"error": {"message": "invalid JSON"}})
            if not str(payload.get("model", "")).endswith("-free"):
                return self._json(400, {"error": {"message": "only OpenCode Free models are allowed"}})
            try:
                response, sock, prefix = app.perform("POST", "/zen/v1/chat/completions", body, self.headers.get("Accept", "*/*"))
                return self._relay(response, sock, prefix)
            except AfterSendError:
                return self._json(502, {"error": {"message": "ambiguous upstream failure; request not replayed"}})
            except Exception:
                return self._json(503, {"error": {"message": "no healthy upstream exit"}})

        def do_PUT(self):
            return self._relay_dynamic("PUT")

        def do_DELETE(self):
            return self._relay_dynamic("DELETE")

        def do_PATCH(self):
            return self._relay_dynamic("PATCH")

        def do_HEAD(self):
            return self._relay_dynamic("HEAD")

        def log_message(self, *_args):
            return

    return Handler


def main():
    key = os.environ.get("GATEWAY_API_KEY", "")
    if not key:
        raise SystemExit("GATEWAY_API_KEY is required")
    adapter = os.environ.get("ADAPTER_URL", "http://worldpool-adapter-qwsm8umlxplwpg8cnndchwrq:3000")
    app = Gateway(StickyPool(), key)

    def refresh():
        try:
            candidates, healthy = app.refresh(adapter)
            print(f"inventory refresh candidates={candidates} healthy={healthy} active={bool(app.pool.current())}", flush=True)
        except Exception as exc:
            print(f"inventory refresh failed type={type(exc).__name__}", flush=True)

    refresh()
    threading.Thread(target=lambda: _refresh_loop(refresh), daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), make_handler(app)).serve_forever()


def _refresh_loop(refresh):
    while True:
        time.sleep(REFRESH_SECONDS)
        refresh()


if __name__ == "__main__":
    main()
