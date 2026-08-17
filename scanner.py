# -*- coding: utf-8 -*-
"""
SiteDoc AI - 実測診断エンジン
外部から観測可能な公開情報のみを用いた非侵入型スキャン。
  1. SSL/TLS 証明書
  2. HTTP セキュリティヘッダー
  3. 認証方式（フィッシング耐性の兆候：WebAuthn/パスキー）
  4. DNS メール認証（SPF / DKIM / DMARC）
  5. 類似・偽装ドメイン（実登録の照会）
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
        conn.request("HEAD", "/", headers={"User-Agent": "SiteDocAI/1.0"})
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


GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)


def _check_security_txt(domain):
    """RFC9116準拠のsecurity.txtを探索。見つかれば内容の要旨を返す。"""
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(domain, 443, timeout=SOCK_TIMEOUT, context=ctx)
            conn.request("GET", path, headers={"User-Agent": "SiteDocAI/1.0"})
            resp = conn.getresponse()
            body = resp.read(4000).decode("utf-8", "replace")
            conn.close()
            if resp.status == 200 and "contact" in body.lower():
                return path
        except Exception:
            continue
    return None


def _cookie_name(raw):
    """Set-Cookie の生値からCookie名だけを取り出す。"""
    first = raw.split(";", 1)[0]
    return first.split("=", 1)[0].strip() if "=" in first else first.strip()


def scan_headers(domain):
    findings = []
    try:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(domain, 443, timeout=SOCK_TIMEOUT, context=ctx)
        conn.request("GET", "/", headers={"User-Agent": "SiteDocAI/1.0"})
        resp = conn.getresponse()
        raw_headers = resp.getheaders()
        # 辞書化すると同名ヘッダーが上書きされるため、Set-Cookie（複数あり得る）は別途保持する
        headers = {k.lower(): v for k, v in raw_headers}
        cookies = [v for k, v in raw_headers if k.lower() == "set-cookie"]
        body = resp.read(200000).decode("utf-8", "replace")
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

    # サーバソフトウェアの鮮度（バージョン開示）
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    exposed = []
    if server and re.search(r"\d", server):
        exposed.append(f"Server: {server}")
    if powered_by:
        exposed.append(f"X-Powered-By: {powered_by}")
    m = GENERATOR_RE.search(body)
    if m:
        exposed.append(f"Generator: {m.group(1)}")
    if exposed:
        findings.append(("w", "サーバソフトウェアの鮮度",
                          "バージョン情報が露出しており、既知の脆弱性を狙われるリスクがあります：" + "、".join(exposed)))
    else:
        findings.append(("s", "サーバソフトウェアの鮮度", "サーバソフトウェアのバージョン情報は非公開です"))

    # Cookieのセキュリティ属性（トップページで発行された分のみ。ログイン後発行のCookieは対象外）
    if cookies:
        missing_secure = [_cookie_name(c) for c in cookies if "secure" not in c.lower()]
        missing_httponly = [_cookie_name(c) for c in cookies if "httponly" not in c.lower()]
        missing_samesite = [_cookie_name(c) for c in cookies if "samesite" not in c.lower()]

        if missing_secure:
            sample = "、".join(missing_secure[:3])
            more = f" ほか{len(missing_secure)-3}件" if len(missing_secure) > 3 else ""
            findings.append(("c", "Cookieのセキュリティ属性（Secure）",
                              f"Secure属性の無いCookieを検出：{sample}{more}。"
                              "HTTP通信に混在した場合、通信内容を盗聴されるリスクがあります"))
        if missing_httponly:
            sample = "、".join(missing_httponly[:3])
            more = f" ほか{len(missing_httponly)-3}件" if len(missing_httponly) > 3 else ""
            findings.append(("w", "Cookieのセキュリティ属性（HttpOnly）",
                              f"HttpOnly属性の無いCookieを検出：{sample}{more}。"
                              "JavaScript経由で読み取れるため、XSS発生時に盗まれるリスクがあります"))
        if missing_samesite:
            sample = "、".join(missing_samesite[:3])
            more = f" ほか{len(missing_samesite)-3}件" if len(missing_samesite) > 3 else ""
            findings.append(("w", "Cookieのセキュリティ属性（SameSite）",
                              f"SameSite属性の無いCookieを検出：{sample}{more}。"
                              "CSRF（意図しないリクエストの偽装）のリスクが上がります"))
        if not (missing_secure or missing_httponly or missing_samesite):
            findings.append(("s", "Cookieのセキュリティ属性",
                              f"検出した{len(cookies)}件のCookieはすべてSecure/HttpOnly/SameSiteが設定済みです"))
    # cookies が空の場合は「トップページでは発行なし」であり不備ではないため、findingは追加しない

    # 脆弱性報告窓口（security.txt）
    sec_path = _check_security_txt(domain)
    if sec_path:
        findings.append(("s", "脆弱性報告窓口（security.txt）", f"{sec_path} が公開されています（脆弱性発見時の報告体制あり）"))
    else:
        findings.append(("w", "脆弱性報告窓口（security.txt）", "security.txtが見つかりません（脆弱性の報告先が外部から分かりません）"))

    return _area("hdr", "セキュリティヘッダー", findings)


# ============================================================
# 3. DNS メール認証（SPF / DKIM / DMARC / DNSSEC）
# ============================================================
# 主要メール基盤の代表的セレクタ。1件ごとにDNS照会が1回増えるため、
# 実在頻度の高いもの中心に絞って追加している（無制限に増やすとレイテンシが伸びる）。
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",       # Google Workspace / Microsoft365
    "k1", "k2", "k3",                                     # Mailchimp
    "s1", "s2",                                           # SendGrid
    "pm",                                                 # Postmark
    "mg", "mta",                                          # Mailgun
    "zmail",                                               # Zoho Mail
    "fm1",                                                 # Fastmail
    "s2048",                                               # Yahoo/AOL系
    "protonmail",                                          # ProtonMail
    "dkim", "mail", "mandrill", "smtp", "mx",              # 汎用・その他
    "mxvault", "amazonses",
]

# RFC 7208: SPFのDNSルックアップ機構は合計10回まで（超過するとpermerrorで無効化される）
_SPF_LOOKUP_RE = re.compile(r"\b(include|a|mx|ptr|exists|redirect)[:=]", re.I)


def _dmarc_next_step(policy, has_rua):
    """現在のDMARCポリシーから、次に公開すべき実レコードを提案する。"""
    if policy in (None, "none"):
        return ('v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@' + '{domain}',
                "まず隔離率25%から開始し、正規メールへの影響が無いことをレポートで確認後に引き上げる")
    if policy == "quarantine":
        return ('v=DMARC1; p=reject; rua=mailto:dmarc-reports@' + '{domain}',
                "隔離運用が安定していれば、最終形の reject（拒否）へ引き上げる")
    return (None, None)  # 既に reject（最終形）


def scan_dns(domain):
    findings = []

    # --- SPF ---
    txts = _txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if not spf:
        findings.append(("c", "SPF", "SPF未設定（第三者による なりすまし送信が可能）。"
                          f'"v=spf1 include:_spf.google.com -all" 等、利用中のメール基盤に'
                          "合わせたレコードを公開してください"))
    else:
        if re.search(r"[-~]all", spf):
            if "-all" in spf:
                findings.append(("s", "SPF", "SPF設定済み（-all：厳格）"))
            else:
                findings.append(("w", "SPF", "SPF設定済みだが ~all（ソフトフェイル）。"
                                  "運用が安定していれば -all（厳格）への引き上げを推奨"))
        else:
            findings.append(("w", "SPF", "SPFの終端指定(all)が緩い、または未指定"))

        # DNSルックアップ回数（RFC7208: 10回超過でSPF自体が無効化される）
        lookups = len(_SPF_LOOKUP_RE.findall(spf))
        if lookups > 10:
            findings.append(("c", "SPFのDNSルックアップ数",
                              f"約{lookups}回（上限10回）。超過するとSPFがpermerrorで無効化され、"
                              "正規メールも含めて認証されなくなります。includeの整理が必要です"))
        elif lookups >= 8:
            findings.append(("w", "SPFのDNSルックアップ数",
                              f"約{lookups}回（上限10回に接近）。今後includeを追加すると"
                              "上限超過のリスクがあります"))

    # --- DMARC ---
    dmarc_txts = _txt("_dmarc." + domain)
    dmarc = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        findings.append(("c", "DMARC", "DMARC未設定（偽メールを検知・拒否できません）。"
                          f'_dmarc.{domain} に "v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}" '
                          "を公開し、まず監視から開始してください"))
    else:
        m = re.search(r"p=(\w+)", dmarc)
        pol = m.group(1).lower() if m else "none"
        rua_m = re.search(r"rua=", dmarc, re.I)
        next_record, next_note = _dmarc_next_step(pol, bool(rua_m))
        next_record = next_record.format(domain=domain) if next_record else None

        if pol == "reject":
            findings.append(("s", "DMARC", "DMARC設定済み（p=reject：最も強い設定で有効に機能）"))
        elif pol == "quarantine":
            findings.append(("s", "DMARC", f"DMARC設定済み（p=quarantine：有効に機能）。"
                              f"次の一歩として {next_note}: 「{next_record}」"))
        else:
            findings.append(("w", "DMARC", f"DMARCが p=none（監視のみで拒否しない）。"
                              f"次の一歩: 「{next_record}」（{next_note}）"))
        if not rua_m:
            findings.append(("w", "DMARC集計レポート",
                              "rua（集計レポート送付先）が未設定です。可視化なしに"
                              "ポリシーを引き上げると正規メールを誤って弾くリスクがあります"))

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
        findings.append(("w", "DKIM", "一般的なセレクタではDKIMを検出できませんでした（要個別確認。"
                          "セレクタは送信側にしか分からないため、未検出=未設定とは限りません）"))

    # --- DNSSEC ---
    has_dnssec = _has_dnssec(domain)
    if has_dnssec:
        findings.append(("s", "DNSSEC", "DNSSEC署名を検出（DNS応答の改ざんを検知可能）"))
    else:
        findings.append(("w", "DNSSEC", "DNSSEC未導入（DNS応答の改ざんを受信側で検知できません。"
                          "正しいURLでも偽サイトへ誘導される「DNS侵害」のリスクが残ります）"))

    return _area("dns", "DNS認証（メール）", findings)


def _has_dnssec(domain):
    """DSレコードの有無でDNSSEC導入を判定（親ゾーンへの署名委任の有無）。"""
    try:
        ans = _resolver.resolve(domain, "DS")
        return len(ans) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout, Exception):
        return False


# ============================================================
# 4. 認証方式（フィッシング耐性の兆候）
# ============================================================
WEBAUTHN_SIGNALS = (
    "webauthn", "passkey", "public-key-credential",
    "navigator.credentials.create", "navigator.credentials.get",
)


def scan_auth(domain):
    findings = []
    try:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(domain, 443, timeout=SOCK_TIMEOUT, context=ctx)
        conn.request("GET", "/", headers={"User-Agent": "SiteDocAI/1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read(200000).decode("utf-8", "replace")
        conn.close()
    except Exception as e:
        findings.append(("w", "認証方式の検出", f"ページを取得できず判定できませんでした（{type(e).__name__}）"))
        return _area("auth", "認証方式（フィッシング耐性）", findings)

    pp = headers.get("permissions-policy", "").lower()
    signal = "publickey-credentials" in pp or any(s in body.lower() for s in WEBAUTHN_SIGNALS)

    if signal:
        findings.append(("s", "パスキー/WebAuthn対応の兆候",
                          "フィッシング耐性のある認証（WebAuthn/パスキー）の実装兆候を検出しました"))
    else:
        findings.append(("w", "パスキー/WebAuthn対応の兆候",
                          "トップページからはパスキー/WebAuthn対応の兆候を検出できませんでした（ログインページの個別確認を推奨、パスワード＋SMS等の旧型認証はフィッシング耐性が低い点に留意）"))

    return _area("auth", "認証方式（フィッシング耐性）", findings)


# ============================================================
# 5. 類似・偽装ドメイン
# ============================================================
# 同形異字（見間違えやすい置換）
_HOMOGLYPHS = {
    "o": ["0"], "0": ["o"], "l": ["1", "i"], "1": ["l", "i"],
    "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"],
    "rn": ["m"], "m": ["rn"], "vv": ["w"], "w": ["vv"],
}
# なりすましメールの送信元・偽装ログインページとして付与されやすい語
_LOOKALIKE_AFFIXES = ["support", "mail", "secure", "login", "account"]


def _lookalike_candidates(domain):
    """紛らわしい類似ドメイン候補を生成（同形異字・欠落・重複・入替・ハイフン・別TLD・付加語）。"""
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    name = parts[0]
    rest = "." + ".".join(parts[1:])
    n = len(name)
    cands = set()

    # 同形異字（複数パターンに対応）
    for pat, reps in _HOMOGLYPHS.items():
        if pat in name:
            for rep in reps:
                cands.add(name.replace(pat, rep, 1) + rest)

    # 1文字省略
    for i in range(n):
        if n > 3:
            cands.add(name[:i] + name[i + 1:] + rest)

    # 隣接文字の入れ替え
    for i in range(n - 1):
        s = list(name)
        s[i], s[i + 1] = s[i + 1], s[i]
        cands.add("".join(s) + rest)

    # 文字重複
    for i in range(n):
        cands.add(name[:i + 1] + name[i] + name[i + 1:] + rest)

    # ハイフンの有無
    if "-" in name:
        cands.add(name.replace("-", "") + rest)
    elif n > 4:
        cands.add(name[:n // 2] + "-" + name[n // 2:] + rest)

    # 別TLDでの登録
    base_tld = parts[-1]
    for tld in ("com", "net", "org", "info", "co", "jp", "co.jp"):
        if tld != base_tld:
            cands.add(name + "." + tld)

    # なりすまし目的の付加語（-support 等）
    for aff in _LOOKALIKE_AFFIXES:
        cands.add(f"{name}-{aff}" + rest)

    cands.discard(domain)
    return list(cands)[:30]  # 探索数を制限（レイテンシと精度のバランス）


def _mx(name):
    """MXレコードの有無。あれば=メール送受信が可能=なりすまし送信に即使える状態。"""
    try:
        ans = _resolver.resolve(name, "MX")
        return len(ans) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout, Exception):
        return False


def scan_phishing(domain):
    findings = []
    cands = _lookalike_candidates(domain)
    if not cands:
        findings.append(("s", "類似ドメイン", "評価対象の類似ドメインはありません"))
        return _area("phish", "フィッシング偽装", findings)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = dict(zip(cands, ex.map(_resolves, cands)))
    registered = [c for c, r in results.items() if r]

    # 登録済みのものだけ、追加でMXの有無を確認する（＝メールを送れる状態か）
    mx_capable = []
    if registered:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            mx_results = dict(zip(registered, ex.map(_mx, registered)))
        mx_capable = [c for c, r in mx_results.items() if r]

    if not registered:
        findings.append(("s", "類似ドメイン登録", "なりすまし可能な類似ドメインは未検出"))
    elif mx_capable:
        # MXが1件でもあれば最優先：なりすましメールを即送信できる状態のため
        sample = "、".join(mx_capable[:3])
        more = f" ほか{len(mx_capable)-3}件" if len(mx_capable) > 3 else ""
        findings.append(("c", "類似ドメインのメール送信能力",
                         f"稼働中かつメール送信可能(MXあり)な類似ドメインを{len(mx_capable)}件検出："
                         f"{sample}{more}。なりすましメールを即座に送信できる状態です"))
        others = len(registered) - len(mx_capable)
        if others > 0:
            findings.append(("w", "類似ドメイン登録（メール送信能力なし）",
                             f"上記以外に、稼働中だがMXの無い類似ドメインが{others}件あります"))
    elif len(registered) == 1:
        findings.append(("w", "類似ドメイン登録",
                         f"稼働中の類似ドメインを1件検出（メール送信能力は無し）：{registered[0]}"))
    else:
        sample = "、".join(registered[:3])
        more = f" ほか{len(registered)-3}件" if len(registered) > 3 else ""
        findings.append(("w", "類似ドメイン登録",
                         f"稼働中の類似ドメインを{len(registered)}件検出（メール送信能力は無し）："
                         f"{sample}{more}"))

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
    """5領域を並列実行して統合レポートを返す。"""
    tasks = {
        "ssl": scan_ssl,
        "hdr": scan_headers,
        "auth": scan_auth,
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

    order = ["ssl", "hdr", "auth", "dns", "phish"]
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
        "becRiskSignal": _bec_risk_signal(area_results),
    }


# ============================================================
# BECアップセル判定
# ============================================================
# なりすまし送金詐欺のリスクが「実際に高い」と言える根拠が揃ったかを判定する。
# server.py・report.py・フロントエンドが同じ基準を参照するよう、判定はここに一元化する。
#
# 判定を厳しめにしている理由:
#   有名ドメインは類似ドメインをほぼ必ず取得されており、「類似ドメインあり」だけを
#   条件にすると全診断で発火してノイズになる（実測でgoogle/example/wikipediaの
#   3件すべてが該当した）。案内が常時出ると価値が薄れ、営業導線として逆効果になる。
#   そこで「なりすまし送信が現に可能な状態」と言える根拠に限定する。
#
# 発火条件（いずれか）:
#   A. なりすまし送信を受信側で止められない … SPF未設定 / DMARC未設定 / DMARC p=none
#   B. 攻撃準備が実在する … 類似ドメインがMXを持つ（＝メールを即送信できる）
_BEC_CRITICAL_TITLES = ("SPF", "DMARC")           # 重大(c)のみ対象。~all等の軽微は除く
_BEC_MX_TITLE = "類似ドメインのメール送信能力"      # MXありの類似ドメイン検出


def _bec_risk_signal(area_results):
    for area in area_results:
        if area["key"] == "dns":
            for f in area["findings"]:
                # SPF/DMARCの「重大」＝未設定またはp=noneのみを根拠とする
                if f["sev"] == "c" and any(
                    f["title"].startswith(t) for t in _BEC_CRITICAL_TITLES
                ):
                    return True
                # p=none は重大ではなく要改善(w)で出るため個別に拾う
                if f["sev"] == "w" and f["title"] == "DMARC" and "p=none" in f["desc"]:
                    return True
        elif area["key"] == "phish":
            for f in area["findings"]:
                if f["title"] == _BEC_MX_TITLE:
                    return True
    return False


if __name__ == "__main__":
    import sys, json
    d = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(full_scan(d), ensure_ascii=False, indent=2))
