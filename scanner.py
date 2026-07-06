# -*- coding: utf-8 -*-
"""
SENTINEL AUDIT - 実測診断エンジン
外部から観測可能な公開情報のみを用いた非侵入型スキャン。
  1. SSL/TLS 証明書
  2. HTTP セキュリティヘッダー
  3. DNS メール認証（SPF / DKIM / DMARC）
  4. 類似・偽装ドメイン（実登録の照会）
"""
import ssl
import socket
import http.client
import datetime
import re
import warnings
import ipaddress
import concurrent.futures

warnings.simplefilter("ignore", DeprecationWarning)

import dns.resolver
import dns.exception

# ---- 深刻度スコア ----
PTS = {"s": 100, "w": 55, "c": 15}

SOCK_TIMEOUT = 7.0
DNS_LIFETIME = 4.0

_resolver = dns.resolver.Resolver()
_resolver.lifetime = DNS_LIFETIME
_resolver.timeout = DNS_LIFETIME


def _txt(name):
    """TXTレコードを取得（文字列のリスト）。無ければ空リスト。"""
    try:
        ans = _resolver.resolve(name, "TXT")
        out = []
        for r in ans:
            # dnspython は各TXTを bytes 断片のタプルで返す
            parts = b"".join(r.strings).decode("utf-8", "replace")
            out.append(parts)
        return out
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout, Exception):
        return []


def domain_exists(name):
    """ドメインが実在するか（NS または A/AAAA が存在するか）。"""
    for rt in ("NS", "A", "AAAA"):
        try:
            _resolver.resolve(name, rt)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.LifetimeTimeout, Exception):
            continue
    return False


def is_public_domain(name):
    """スキャン対象が公開ホストか検証する（SSRF/踏み台防止ガード）。
    名前解決した全IPが グローバルな公開アドレス であることを確認する。
    戻り値: (ok: bool, reason: str)
      reason = "ok" / "notfound"（未登録） / "internal"（内部・予約アドレス）
    """
    ips = []
    for rt in ("A", "AAAA"):
        try:
            for r in _resolver.resolve(name, rt):
                ips.append(str(r))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.LifetimeTimeout, Exception):
            continue
    if not ips:
        return (False, "notfound")
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return (False, "internal")
        # プライベート/ループバック/リンクローカル(169.254.x=クラウドメタデータ)/
        # 予約/マルチキャストなど、公開でないアドレスは全て拒否
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast
                or addr.is_unspecified or not addr.is_global):
            return (False, "internal")
    return (True, "ok")


def _resolves(name):
    """A/AAAAレコードが存在する（=登録・稼働している）か。"""
    for rt in ("A", "AAAA"):
        try:
            _resolver.resolve(name, rt)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.LifetimeTimeout, Exception):
            continue
    return False


# ============================================================
# 1. SSL / TLS 証明書
# ============================================================
def scan_ssl(domain):
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=SOCK_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
    except ssl.SSLCertVerificationError as e:
        findings.append(("c", "証明書の検証", f"証明書の検証に失敗しました（{e.verify_message}）"))
        findings.append(("c", "暗号化プロトコル", "有効なTLS接続を確立できませんでした"))
        findings.append(("c", "HTTPSリダイレクト", "HTTPSでの接続が確認できません"))
        return _area("ssl", "SSL/TLS証明書", findings)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        findings.append(("c", "HTTPS接続", f"443番ポートへ接続できませんでした（{type(e).__name__}）"))
        findings.append(("c", "暗号化プロトコル", "TLS接続を確立できませんでした"))
        return _area("ssl", "SSL/TLS証明書", findings)

    # --- 有効期限 ---
    try:
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (not_after - datetime.datetime.now()).days
        if days < 0:
            findings.append(("c", "証明書の有効期限", f"証明書は{abs(days)}日前に失効しています"))
        elif days <= 15:
            findings.append(("c", "証明書の有効期限", f"残り{days}日で失効します（緊急更新が必要）"))
        elif days <= 30:
            findings.append(("w", "証明書の有効期限", f"残り{days}日で失効します（早めの更新を推奨）"))
        else:
            findings.append(("s", "証明書の有効期限", f"有効期限まで残り{days}日（余裕あり）"))
    except Exception:
        findings.append(("w", "証明書の有効期限", "有効期限を解析できませんでした"))

    # --- 発行元 ---
    try:
        issuer = dict(x[0] for x in cert["issuer"])
        org = issuer.get("organizationName", issuer.get("commonName", "不明"))
        findings.append(("s", "証明書の発行元", f"信頼された認証局が発行：{org}"))
    except Exception:
        pass

    # --- 交渉されたプロトコル ---
    if proto in ("TLSv1.3", "TLSv1.2"):
        findings.append(("s", "暗号化プロトコル", f"最新の {proto} で接続（安全）"))
    elif proto in ("TLSv1.1", "TLSv1"):
        findings.append(("c", "暗号化プロトコル", f"非推奨の {proto} で接続されました"))
    else:
        findings.append(("w", "暗号化プロトコル", f"接続プロトコル：{proto}"))

    # --- 旧プロトコル(TLS1.0/1.1)の受け入れ確認 ---
    legacy = _check_legacy_tls(domain)
    if legacy is True:
        findings.append(("c", "旧プロトコルの無効化", "非推奨のTLS1.0/1.1が有効なままです"))
    elif legacy is False:
        findings.append(("s", "旧プロトコルの無効化", "TLS1.0/1.1は無効化されています"))
    # legacy is None → 判定不能（環境依存）のため項目を追加しない

    # --- HTTP→HTTPS リダイレクト ---
    redir = _check_https_redirect(domain)
    if redir == "ok":
        findings.append(("s", "HTTPSリダイレクト", "HTTPアクセスはHTTPSへ自動転送されます"))
    elif redir == "no":
        findings.append(("c", "HTTPSリダイレクト", "HTTPが暗号化されずに応答しています"))
    # 不明なら追加しない

    return _area("ssl", "SSL/TLS証明書", findings)


def _check_legacy_tls(domain):
    """TLS1.1以下で握手を試み、成立するか確認。True=旧有効, False=拒否, None=判定不能"""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, AttributeError):
        return None  # このOpenSSLでは旧TLSを設定できない
    try:
        with socket.create_connection((domain, 443), timeout=SOCK_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                v = ss.version()
                return v in ("TLSv1", "TLSv1.1")
    except ssl.SSLError:
        return False  # サーバが旧TLSを拒否
    except Exception:
        return None


def _check_https_redirect(domain):
    try:
        conn = http.client.HTTPConnection(domain, 80, timeout=SOCK_TIMEOUT)
        conn.request("HEAD", "/", headers={"User-Agent": "SentinelAudit/1.0"})
        resp = conn.getresponse()
        loc = resp.getheader("Location", "") or ""
        conn.close()
        if 300 <= resp.status < 400 and loc.lower().startswith("https://"):
            return "ok"
        if resp.status < 400:
            return "no"
        return "unknown"
    except Exception:
        return "unknown"


# ============================================================
# 2. HTTP セキュリティヘッダー
# ============================================================
HEADER_CHECKS = [
    ("strict-transport-security", "HSTS",
     "通信の常時暗号化を強制", "中間者攻撃を防ぐHSTSが未設定です"),
    ("content-security-policy", "Content-Security-Policy",
     "XSS等を抑止するCSPを定義済み", "CSP未設定（XSSを防ぎにくい状態）"),
    ("x-frame-options", "X-Frame-Options",
     "クリックジャッキング対策済み", "X-Frame-Options未設定"),
    ("x-content-type-options", "X-Content-Type-Options",
     "MIMEタイプ推測を防止", "X-Content-Type-Options未設定"),
    ("referrer-policy", "Referrer-Policy",
     "リファラ情報の漏えいを制御", "Referrer-Policy未設定"),
    ("permissions-policy", "Permissions-Policy",
     "ブラウザ機能の利用を制限", "Permissions-Policy未設定"),
]

# 重要度：未設定時に crit 扱いにするヘッダー
CRIT_IF_MISSING = {"strict-transport-security", "content-security-policy"}


def scan_headers(domain):
    findings = []
    try:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(domain, 443, timeout=SOCK_TIMEOUT, context=ctx)
        conn.request("GET", "/", headers={"User-Agent": "SentinelAudit/1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
    except Exception as e:
        findings.append(("c", "ヘッダー取得", f"HTTP応答を取得できませんでした（{type(e).__name__}）"))
        return _area("hdr", "セキュリティヘッダー", findings)

    for key, label, ok_msg, miss_msg in HEADER_CHECKS:
        if key in headers:
            findings.append(("s", label, ok_msg))
        else:
            sev = "c" if key in CRIT_IF_MISSING else "w"
            findings.append((sev, label, miss_msg))

    # サーバ情報の露出
    server = headers.get("server", "")
    if server and re.search(r"\d", server):
        findings.append(("w", "サーバ情報の露出", f"Serverヘッダーでバージョンが露出：{server}"))

    return _area("hdr", "セキュリティヘッダー", findings)


# ============================================================
# 3. DNS メール認証（SPF / DKIM / DMARC）
# ============================================================
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim",
                  "mail", "s1", "s2", "mandrill", "smtp", "mx"]


def scan_dns(domain):
    findings = []

    # --- SPF ---
    txts = _txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if not spf:
        findings.append(("c", "SPF", "SPF未設定（第三者による なりすまし送信が可能）"))
    else:
        if re.search(r"[-~]all", spf):
            if "-all" in spf:
                findings.append(("s", "SPF", "SPF設定済み（-all：厳格）"))
            else:
                findings.append(("w", "SPF", "SPF設定済みだが ~all（ソフトフェイル）"))
        else:
            findings.append(("w", "SPF", "SPFの終端指定(all)が緩い、または未指定"))

    # --- DMARC ---
    dmarc_txts = _txt("_dmarc." + domain)
    dmarc = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        findings.append(("c", "DMARC", "DMARC未設定（偽メールを検知・拒否できません）"))
    else:
        m = re.search(r"p=(\w+)", dmarc)
        pol = m.group(1).lower() if m else "none"
        if pol in ("reject", "quarantine"):
            findings.append(("s", "DMARC", f"DMARC設定済み（p={pol}：有効に機能）"))
        else:
            findings.append(("w", "DMARC", "DMARCが p=none（監視のみで拒否しない）"))

    # --- DKIM（代表的なセレクタを探索）---
    found_sel = None
    for sel in DKIM_SELECTORS:
        rec = _txt(f"{sel}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in rec):
            found_sel = sel
            break
    if found_sel:
        findings.append(("s", "DKIM", f"DKIM署名を検出（セレクタ：{found_sel}）"))
    else:
        findings.append(("w", "DKIM", "一般的なセレクタではDKIMを検出できませんでした（要個別確認）"))

    return _area("dns", "DNS認証（メール）", findings)


# ============================================================
# 4. 類似・偽装ドメイン
# ============================================================
def _lookalikes(domain):
    """紛らわしい類似ドメイン候補を生成。"""
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    name = parts[0]
    rest = "." + ".".join(parts[1:])
    cands = set()

    # 文字の視覚的置換
    subs = [("o", "0"), ("0", "o"), ("l", "1"), ("1", "l"),
            ("i", "1"), ("rn", "m"), ("m", "rn"), ("e", "3")]
    for a, b in subs:
        if a in name:
            cands.add(name.replace(a, b, 1) + rest)

    # ハイフンの有無
    if "-" in name:
        cands.add(name.replace("-", "") + rest)
    else:
        # よくある区切り位置にハイフン挿入（先頭寄り）
        if len(name) > 4:
            cands.add(name[:len(name)//2] + "-" + name[len(name)//2:] + rest)

    # 文字重複・欠落
    if len(name) > 3:
        cands.add(name + name[-1] + rest)          # 末尾重複
        cands.add(name[:-1] + rest)                # 末尾欠落

    # 別TLDでの登録
    base_tld = parts[-1]
    for tld in ("com", "net", "org", "info", "co"):
        if tld != base_tld:
            cands.add(name + "." + tld)

    cands.discard(domain)
    return list(cands)[:18]  # 探索数を制限


def scan_phishing(domain):
    findings = []
    cands = _lookalikes(domain)
    if not cands:
        findings.append(("s", "類似ドメイン", "評価対象の類似ドメインはありません"))
        return _area("phish", "フィッシング偽装", findings)

    registered = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = dict(zip(cands, ex.map(_resolves, cands)))
    registered = [c for c, r in results.items() if r]

    if not registered:
        findings.append(("s", "類似ドメイン登録", "なりすまし可能な類似ドメインは未検出"))
    elif len(registered) == 1:
        findings.append(("w", "類似ドメイン登録",
                         f"稼働中の類似ドメインを1件検出：{registered[0]}"))
    else:
        sample = "、".join(registered[:3])
        more = f" ほか{len(registered)-3}件" if len(registered) > 3 else ""
        findings.append(("c", "類似ドメイン登録",
                         f"稼働中の類似ドメインを{len(registered)}件検出：{sample}{more}"))

    # 参考：登録の有無だけでは悪性と断定できない旨は報告書側で明記
    findings.append(("s", "調査範囲", f"視覚的に紛らわしい候補{len(cands)}件を照会しました"))

    return _area("phish", "フィッシング偽装", findings)


# ============================================================
# 集計
# ============================================================
def _area(key, name, findings):
    if not findings:
        findings = [("w", "診断", "有効なデータを取得できませんでした")]
    score = round(sum(PTS[f[0]] for f in findings) / len(findings))
    return {
        "key": key,
        "name": name,
        "score": score,
        "findings": [{"sev": f[0], "title": f[1], "desc": f[2]} for f in findings],
    }


def full_scan(domain):
    """4領域を並列実行して統合レポートを返す。"""
    tasks = {
        "ssl": scan_ssl,
        "hdr": scan_headers,
        "dns": scan_dns,
        "phish": scan_phishing,
    }
    areas = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(fn, domain): k for k, fn in tasks.items()}
        for fut in concurrent.futures.as_completed(futs):
            k = futs[fut]
            try:
                areas[k] = fut.result()
            except Exception as e:
                areas[k] = _area(k, tasks[k].__name__,
                                 [("c", "診断エラー", f"{type(e).__name__}: {e}")])

    order = ["ssl", "hdr", "dns", "phish"]
    area_results = [areas[k] for k in order if k in areas]

    counts = {"c": 0, "w": 0, "s": 0}
    for a in area_results:
        for f in a["findings"]:
            counts[f["sev"]] += 1

    overall = round(sum(a["score"] for a in area_results) / len(area_results)) if area_results else 0

    return {
        "domain": domain,
        "overall": overall,
        "counts": counts,
        "areaResults": area_results,
        "scannedAt": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


if __name__ == "__main__":
    import sys, json
    d = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(full_scan(d), ensure_ascii=False, indent=2))
