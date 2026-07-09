# -*- coding: utf-8 -*-
"""
サイバードッグ診断 - 診断サーバー
  GET /              → フロントエンド（public/index.html）
  GET /api/scan?domain=example.co.jp → 実測診断をJSONで返す
"""
import json
import re
import os
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

import scanner
import report as report_gen

# 本番（Render等）では PORT 環境変数が渡される。その場合は 0.0.0.0 で待受。
# ローカル単体起動時は 127.0.0.1（自PC内のみ）。
PORT = int(os.environ.get("PORT", "8787"))
HOST = os.environ.get("HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")

# 本サイト自身に付与するセキュリティヘッダー（診断ツールが自分のテストに合格するように）
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    ),
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)

# --- 簡易レート制限（同一IP：直近60秒に10回まで）---
_rl_lock = threading.Lock()
_rl = {}  # ip -> [timestamps]

def _rate_ok(ip):
    now = time.time()
    with _rl_lock:
        hits = [t for t in _rl.get(ip, []) if now - t < 60]
        if len(hits) >= 10:
            _rl[ip] = hits
            return False
        hits.append(now)
        _rl[ip] = hits
        return True


def clean_domain(raw):
    d = (raw or "").strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split("?")[0].strip()
    d = re.sub(r":\d+$", "", d)  # ポート除去
    return d


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberDog/1.0"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _client_ip(self):
        # リバースプロキシ（Render等）越しでは実クライアントIPは X-Forwarded-For に入る
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            return self._serve_file("index.html", "text/html; charset=utf-8")

        if path in ("/scan", "/scan.html"):
            return self._serve_file("scan.html", "text/html; charset=utf-8")

        if path == "/api/scan":
            return self._handle_scan(parse_qs(parsed.query))

        if path == "/api/report":
            return self._handle_report(parse_qs(parsed.query))

        if path == "/api/health":
            return self._json(200, {"status": "ok"})

        # 静的ファイル（public配下のみ、パストラバーサル防止）
        safe = os.path.normpath(path).lstrip("\\/").replace("..", "")
        candidate = os.path.join(PUBLIC_DIR, safe)
        if os.path.isfile(candidate):
            if candidate.endswith(".html"):
                ctype = "text/html; charset=utf-8"
            elif candidate.endswith(".svg"):
                ctype = "image/svg+xml"
            elif candidate.endswith(".png"):
                ctype = "image/png"
            else:
                ctype = "application/octet-stream"
            return self._serve_file(safe, ctype)

        return self._json(404, {"error": "not found"})

    def _serve_file(self, rel, ctype):
        full = os.path.join(PUBLIC_DIR, rel)
        try:
            with open(full, "rb") as f:
                self._send(200, f.read(), ctype)
        except FileNotFoundError:
            self._json(404, {"error": "file not found"})

    def _guard_domain(self, qs):
        """レート制限・形式検証・SSRFガードを通す。
        OKなら domain を、NGなら None を返し（その場でエラー応答済み）。"""
        ip = self._client_ip()
        if not _rate_ok(ip):
            self._json(429, {"error": "リクエストが多すぎます。しばらくお待ちください。"})
            return None
        raw = (qs.get("domain") or [""])[0]
        domain = clean_domain(raw)
        if not domain or not DOMAIN_RE.match(domain):
            self._json(400, {"error": "ドメインの形式が正しくありません（例：example.co.jp）"})
            return None
        # SSRF/踏み台防止：内部・プライベート宛先は診断しない
        ok, reason = scanner.is_public_domain(domain)
        if not ok:
            if reason == "notfound":
                self._json(404, {"error": "このドメインは実在しないか、DNSに登録されていないようです。"})
            else:
                print(f"  ! blocked non-public target: {domain}")
                self._json(400, {"error": "このドメインは内部・プライベート宛先を指すため診断できません。公開ドメインを指定してください。"})
            return None
        return domain

    def _handle_scan(self, qs):
        domain = self._guard_domain(qs)
        if not domain:
            return
        print(f"  → scanning: {domain}  (from {self._client_ip()})")
        t0 = time.time()
        try:
            report = scanner.full_scan(domain)
            report["elapsed"] = round(time.time() - t0, 1)
            return self._json(200, report)
        except Exception as e:
            print(f"  ! scan error: {type(e).__name__}: {e}")
            return self._json(500, {"error": f"診断中にエラーが発生しました（{type(e).__name__}）"})

    def _handle_report(self, qs):
        domain = self._guard_domain(qs)
        if not domain:
            return
        print(f"  → report(quick): {domain}  (from {self._client_ip()})")
        try:
            rep = scanner.full_scan(domain)
            data = report_gen.generate_bytes(rep, mode="quick")
        except Exception as e:
            print(f"  ! report error: {type(e).__name__}: {e}")
            return self._json(500, {"error": f"報告書の生成に失敗しました（{type(e).__name__}）"})
        # Content-Dispositionはlatin-1しか通らないため、ASCIIフォールバック名 +
        # RFC 5987のfilename*で日本語のファイル名を渡す
        safe = re.sub(r"[^A-Za-z0-9.\-]", "_", domain)
        ascii_fname = f"CyberDog_{safe}_quickscan.docx"
        utf8_fname = quote(f"サイバードッグ診断_{safe}_quickscan.docx")
        self.send_response(200)
        self.send_header("Content-Type",
                         "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{ascii_fname}"; filename*=UTF-8\'\'{utf8_fname}'
        )
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("=" * 52)
    print("  サイバードッグ診断  診断サーバー起動")
    print(f"  ブラウザで開く:  http://{HOST}:{PORT}/")
    print("  停止: Ctrl + C")
    print("=" * 52)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n停止しました。")
        srv.shutdown()


if __name__ == "__main__":
    main()
