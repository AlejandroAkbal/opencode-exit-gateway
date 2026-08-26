import http.client
import json
import socketserver
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gateway import Gateway, Proxy, StickyPool, filter_free_models, make_handler


BODY = json.dumps({"model": "mimo-v2.5-free", "messages": [{"role": "user", "content": "hello"}]}).encode()


class FakeProxy(socketserver.StreamRequestHandler):
    def handle(self):
        connect = self.rfile.readline()
        while self.rfile.readline() not in (b"\r\n", b"\n", b""):
            pass
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        request = self.rfile.readline()
        headers = {}
        while True:
            line = self.rfile.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            key, value = line.decode().split(":", 1)
            headers[key.lower()] = value.strip()
        body = self.rfile.read(int(headers.get("content-length", "0")))
        self.server.requests.append((request.decode().strip(), body))
        if request.startswith(b"GET "):
            payload = b'{"object":"list","data":[{"id":"paid"},{"id":"mimo-v2.5-free"}]}'
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)
        elif self.server.fail:
            payload = b'{"error":"rate limited"}'
            self.wfile.write(b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)
        else:
            payload = b'{"id":"ok","choices":[{"message":{"content":"done"}}]}'
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)


class FakeProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, fail):
        super().__init__(("127.0.0.1", 0), FakeProxy)
        self.fail = fail
        self.requests = []


class GatewayContract(unittest.TestCase):
    def setUp(self):
        self.a = FakeProxyServer(True)
        self.b = FakeProxyServer(False)
        for server in (self.a, self.b):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        pool = StickyPool([
            Proxy("http", "127.0.0.1", self.a.server_address[1]),
            Proxy("http", "127.0.0.1", self.b.server_address[1]),
        ])
        self.app = Gateway(pool, api_key="secret", upstream_host="ignored", upstream_port=80, upstream_tls=False, retries=1)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        for server in (self.httpd, self.a, self.b):
            server.shutdown()
            server.server_close()

    def post(self, key="secret", body=BODY):
        conn = http.client.HTTPConnection(*self.httpd.server_address, timeout=5)
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"
        conn.request("POST", "/v1/chat/completions", body, headers)
        response = conn.getresponse()
        result = response.status, response.read()
        conn.close()
        return result

    def models(self):
        conn = http.client.HTTPConnection(*self.httpd.server_address, timeout=5)
        conn.request("GET", "/v1/models", headers={"Authorization": "Bearer secret"})
        response = conn.getresponse()
        result = response.status, json.loads(response.read())
        conn.close()
        return result

    def test_429_is_hidden_exactly_replayed_and_replacement_sticks(self):
        status, _ = self.post()
        self.assertEqual(status, 200)
        self.assertEqual(self.a.requests[0][1], BODY)
        self.assertEqual(self.b.requests[0][1], BODY)

        status, _ = self.post()
        self.assertEqual(status, 200)
        self.assertEqual(len(self.a.requests), 1)
        self.assertEqual(len(self.b.requests), 2)

    def test_authentication_is_required(self):
        self.assertEqual(self.post(key=None)[0], 401)
        self.assertEqual(self.post(key="wrong")[0], 401)

    def test_non_free_model_is_rejected_before_upstream(self):
        body = json.dumps({"model": "claude-sonnet-5", "messages": []}).encode()
        self.assertEqual(self.post(body=body)[0], 400)
        self.assertEqual(self.a.requests, [])
        self.assertEqual(self.b.requests, [])

    def test_model_catalog_contains_only_free_models(self):
        catalog = {"object": "list", "data": [{"id": "paid"}, {"id": "mimo-v2.5-free"}]}
        self.assertEqual(filter_free_models(catalog)["data"], [{"id": "mimo-v2.5-free"}])

    def test_model_endpoint_filters_after_prefix_inspection(self):
        status, catalog = self.models()
        self.assertEqual(status, 200)
        self.assertEqual(catalog["data"], [{"id": "mimo-v2.5-free"}])


if __name__ == "__main__":
    unittest.main()
