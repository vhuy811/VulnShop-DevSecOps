#!/usr/bin/env python3
"""
Engine tuong quan SAST - DAST cho do an DevSecOps.

Luong xu ly:
    semgrep.sarif     (nghi ngo o dau)
    sanitizers.sarif  (cho nao da co bang chung an toan)
    routes_map.json   (dong code nao thuoc URL nao)
        |
        v
    Voi moi canh bao:
      1. Anh xa (file, dong) -> (URL, ten tham so)
      2. Neu trong cung action co bang chung sanitizer cung ho CWE -> FILTERED
      3. Nguoc lai, nho OWASP ZAP ban payload vao dung (URL, tham so)
           - ZAP khai thac duoc  -> CONFIRMED
           - Khong khai thac duoc -> UNCONFIRMED  (KHONG phai duong tinh gia)

Nguyen tac: im lang khong phai bang chung. Chi bang chung tinh moi duoc
phep day mot canh bao sang FILTERED; viec ZAP that bai chi dan toi UNCONFIRMED.

Cach dung:
    # Giai doan 1 - kiem tra anh xa va FILTERED, chua can ZAP
    python tools/correlate.py --dry-run

    # Giai doan 2 - co ZAP
    python tools/correlate.py --zap http://localhost:8090 \\
        --base-url http://host.docker.internal:5000 --fail-on-confirmed
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

try:
    import requests
except ImportError:
    requests = None  # chi can khi thuc su goi ZAP

CWE_RE = re.compile(r"CWE-(\d+)")
CONFIDENCE_RANK = {"false positive": 0, "low": 1, "medium": 2, "high": 3, "confirmed": 4}

CONFIRMED = "CONFIRMED"
UNCONFIRMED = "UNCONFIRMED"
FILTERED = "FILTERED"

# --------------------------------------------------------------------------
# BANG ANH XA CWE -> ACTIVE SCAN RULE CUA ZAP
# --------------------------------------------------------------------------
# Day la ban le cua ca he thong. CWE nao co mat trong bang nay thi canh bao
# tinh mang CWE do moi co duong di toi nhan CONFIRMED. CWE khong co mat thi
# khong phai "chua kiem tra" - la "KHONG CO CONG CU DE KIEM TRA", va hai chuyen
# do phai duoc bao cao khac nhau.
#
# Doi chieu voi https://www.zaproxy.org/docs/alerts/ ngay 2026-09-24.
#
# CACH CHON SCANNER - doi tu doi TEN sang doi cweId. Ly do la hai loi that,
# khong phai so thich:
#
#   1. Doi ten bat nham. Chuoi "SQL Injection" nam GON trong ten
#      "NoSQL Injection - MongoDB", ma rule do la CWE-943 chu khong phai CWE-89.
#      Bang cu bat nham hai rule MongoDB moi lan gap mot canh bao SQL Injection.
#
#   2. Doi ten hong hoan toan khi ZAP chay ngon ngu khac. Ten scanner lay qua
#      Constant.messages.getString(...) nen duoc dich. ZAP cai ban tieng Phap
#      thi khong tu khoa tieng Anh nao khop, va tung rule mot im lang khong
#      duoc bat - khong co thong bao loi nao.
#
# Truong `cweId` CO trong ket qua /JSON/ascan/view/scanners/ (dang chuoi, vi du
# "89"), cung voi id, name, quality, enabled. Doi theo so CWE la chinh xac va
# khong phu thuoc ngon ngu.
#
#   ten       : chi de in ra cho nguoi doc, va lam duong lui neu ZAP qua cu
#               khong tra cweId
#   loai_tru  : cac chuoi khien duong lui theo ten bat nham (chi dung khi lui)
#   chi_id    : khi nhieu rule cung mang mot cweId nhung kiem thu viec khac han,
#               ghim dung id can dung. Vi du CWE-94 duoc ca "Server Side Code
#               Injection" (90019 - dung cai ta can) lan "ELMAH Information
#               Leak" (40028) va ".htaccess Information Leak" (40032) khai bao.
CWE_ZAP_SCANNER: dict[str, dict] = {
    "CWE-89":  {"ten": "SQL Injection",            "loai_tru": ("NoSQL",), "chi_id": None},
    "CWE-79":  {"ten": "Cross Site Scripting",     "loai_tru": (),         "chi_id": None},
    "CWE-78":  {"ten": "Remote OS Command Injection", "loai_tru": (),
                "chi_id": {"90020", "90037"}},
    "CWE-22":  {"ten": "Path Traversal",           "loai_tru": (),         "chi_id": None},
    "CWE-643": {"ten": "XPath Injection",          "loai_tru": (),         "chi_id": None},
    "CWE-611": {"ten": "XML External Entity Attack", "loai_tru": (),       "chi_id": None},
    "CWE-918": {"ten": "Server Side Request Forgery", "loai_tru": (),      "chi_id": None},
    "CWE-601": {"ten": "External Redirect",        "loai_tru": (),         "chi_id": None},
    "CWE-90":  {"ten": "LDAP Injection",           "loai_tru": (),         "chi_id": None},
    "CWE-91":  {"ten": "XSLT Injection",           "loai_tru": (),         "chi_id": None},
    "CWE-113": {"ten": "CRLF Injection",           "loai_tru": (),         "chi_id": None},
    "CWE-94":  {"ten": "Server Side Code Injection", "loai_tru": (),
                "chi_id": {"90019"}},
}


# --------------------------------------------------------------------------
# Doc SARIF
# --------------------------------------------------------------------------
def load_sarif_results(path: Path) -> list[dict]:
    """Rut cac ket qua can thiet tu mot file SARIF cua Semgrep."""
    if not path.exists():
        raise SystemExit(f"Khong tim thay {path}. Chay Semgrep xuat SARIF truoc.")

    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for run in data.get("runs", []):
        # Dinh nghia rule nam rieng o tool.driver.rules, khong nam trong ket qua.
        rules = {r.get("id"): r
                 for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

        for res in run.get("results", []):
            msg = res.get("message", {}).get("text", "")
            loc = res.get("locations", [{}])[0]
            phys = loc.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)

            # Tim ma CWE o CA HAI cho, theo dung thu tu:
            #   1. Thong diep - rule tu viet cua do an ghi "CWE-89: ..." o day
            #   2. Dinh nghia rule - rule cong dong de trong properties.tags,
            #      dang "CWE-209: Generation of Error Message..."
            #
            # Truoc day chi doc thong diep, nen moi canh bao tu bat ky bo rule
            # duoc bao tri nao deu thanh UNKNOWN va khong bao gio duoc doi sanh.
            # Mot dong do khoa chat kha nang dung rule cua nguoi khac.
            m = CWE_RE.search(msg)
            if not m:
                m = CWE_RE.search(json.dumps(rules.get(res.get("ruleId", "")), ensure_ascii=False))
            cwe = f"CWE-{m.group(1)}" if m else "UNKNOWN"

            out.append(
                {
                    "rule_id": res.get("ruleId", ""),
                    "cwe": cwe,
                    "file": uri.replace("\\", "/").lstrip("./"),
                    "line": line,
                    "message": msg.strip().split("\n")[0][:110],
                }
            )
    return out


# --------------------------------------------------------------------------
# Anh xa vi tri trong ma nguon sang route
# --------------------------------------------------------------------------
VIEW_RE = re.compile(r"Views/(?P<controller>[^/]+)/(?P<action>[^/]+)\.cshtml$", re.I)


def find_route(file: str, line: int, routes: list[dict]) -> dict | None:
    """
    Tim route chua vi tri (file, dong).

    Hai duong:
      - File Controller: so khop khoang dong cua action.
      - File Razor View: suy ra theo quy uoc Views/<Controller>/<Action>.cshtml.
        Can duong nay vi Semgrep bao loi C3 ngay trong file .cshtml,
        noi khong co khai bao route nao ca.
    """
    for r in routes:
        if r["file"] == file and r["line_start"] <= line <= r["line_end"]:
            return r

    m = VIEW_RE.search(file)
    if m:
        controller = m.group("controller")
        action = m.group("action")
        for r in routes:
            if r["controller"].lower() == controller.lower() and r["action"].lower() == action.lower():
                return r
    return None


def seed_for(route: dict, param: str) -> str:
    """
    Gia tri moi gui kem tham so khi bat dau kiem thu.

    Quan trong hon ve ngoai. ZAP ket luan SQLi chu yeu bang cach SO SANH
    phan hoi giua cac payload (vi du `1 AND 1=1` so voi `1 AND 1=2`).
    Neu gia tri moi da khien app tra ve trang loi hoac trang rong ngay tu
    request nen, thi khong con gi de so sanh va lo hong that van co the
    khong bi phat hien.

    Uu tien gia tri ghi tay trong routes_map.json (khoa `test_seed`),
    sau do moi den suy doan theo ten tham so.
    """
    if route.get("test_seed"):
        return str(route["test_seed"])
    if re.search(r"(^|_)id$|^id", param, re.I):
        return "1"          # id hop le -> tra ve mot ban ghi that
    return "a"              # chuoi khop nhieu san pham -> tra ve danh sach khong rong


def has_sanitizer_evidence(route: dict, cwe: str, sanitizers: list[dict]) -> dict | None:
    """
    Tra ve bang chung sanitizer neu trong CUNG action co sanitizer cung ho CWE.

    Pham vi co y hep o muc action: mot sanitizer o action khac khong noi len
    dieu gi ve action dang xet.
    """
    for s in sanitizers:
        if s["cwe"] != cwe:
            continue
        if s["file"] == route["file"] and route["line_start"] <= s["line"] <= route["line_end"]:
            return s
    return None


# --------------------------------------------------------------------------
# OWASP ZAP
# --------------------------------------------------------------------------
class Zap:
    def __init__(self, endpoint: str, api_key: str = "", timeout: int = 180):
        if requests is None:
            raise SystemExit("Thieu thu vien requests. Chay: pip install requests")
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _get(self, path: str, **params) -> dict:
        if self.api_key:
            params["apikey"] = self.api_key
        url = f"{self.endpoint}{path}?{urlencode(params)}"
        resp = requests.get(url, timeout=30)
        if resp.status_code >= 400:
            # ZAP ghi ly do that trong than phan hoi (vi du url_not_found).
            # raise_for_status() vut mat phan nay, khien moi loi deu tro thanh
            # "400 Bad Request" vo nghia. Giu lai de con biet duong ma sua.
            raise RuntimeError(f"ZAP tra ve {resp.status_code} tai {path}: "
                               f"{resp.text[:400]}")
        return resp.json()

    def ping(self) -> str:
        return self._get("/JSON/core/view/version/").get("version", "?")

    def tune_scanners(self, cwe: str, strength: str = "HIGH",
                      threshold: str = "LOW") -> list[str]:
        """
        Bat va tang do nhay cac active scan rule cua ZAP ung voi mot ma CWE.

        Vi sao can: policy mac dinh cua ZAP chay o cuong do MEDIUM va nguong
        canh bao MEDIUM. O muc do, ZAP thu it payload va chi bao khi rat chac,
        nen lo hong co that van co the khong bi phat hien. Pipeline tu cau hinh
        scanner theo CWE cua canh bao SAST se sat muc tieu hon nhieu.

        Luu y ve pham vi: ham nay CHI BAT THEM, khong tat bat ky rule nao khac.
        Cac rule con lai trong policy van chay binh thuong. Do la co y - muc
        tieu la khong bo sot, con viec dan huong the hien o cho ho rule lien
        quan duoc day len HIGH/LOW chu khong phai o cho tat bot.

        Tra ve danh sach rule da chinh de ghi vao bao cao (tai lap duoc).
        """
        spec = CWE_ZAP_SCANNER.get(cwe)
        if spec is None:
            return []

        so_cwe = cwe.split("-")[-1]
        scanners = self._get("/JSON/ascan/view/scanners/").get("scanners", [])

        # ZAP hien tai tra ve truong cweId cho tung scanner. Chi khi KHONG tim
        # thay truong do o bat ky scanner nao (ban ZAP qua cu) moi lui ve doi
        # ten - kem theo danh sach loai_tru de khong vo phai ho rule khac.
        co_cweid = any(str(s.get("cweId", "0")) not in ("", "0", "None")
                       for s in scanners)

        chon = []
        for s in scanners:
            sid = str(s.get("id", ""))
            ten = s.get("name", "")
            if co_cweid:
                hop = str(s.get("cweId", "")) == so_cwe
            else:
                thap = ten.lower()
                hop = (spec["ten"].lower() in thap
                       and not any(x.lower() in thap for x in spec["loai_tru"]))
            if not hop:
                continue
            if spec["chi_id"] and sid not in spec["chi_id"]:
                continue
            chon.append((sid, ten))

        if not co_cweid:
            print("    (!) Ban ZAP nay khong tra ve cweId - dang lui ve doi ten "
                  "scanner. Ket qua co the sai neu ZAP chay ngon ngu khac tieng Anh.")

        tuned = []
        for sid, ten in chon:
            try:
                self._get("/JSON/ascan/action/enableScanners/", ids=sid)
                self._get("/JSON/ascan/action/setScannerAttackStrength/",
                          id=sid, attackStrength=strength)
                self._get("/JSON/ascan/action/setScannerAlertThreshold/",
                          id=sid, alertThreshold=threshold)
                tuned.append(f"{sid} {ten}")
            except Exception as exc:
                print(f"    (!) Khong chinh duoc rule {sid} {ten}: {exc}")
        return tuned

    def access_url(self, url: str) -> None:
        """
        BAT BUOC truoc khi active scan.
        URL chua nam trong Sites tree thi ascan khong co gi de quet
        va se tra ve sach se - day la loi hay gap nhat khi dieu khien ZAP qua API.

        Neu ZAP khong voi toi duoc app thi bao loi NGAY tai day. Khong duoc
        de im lang roi bien thanh UNCONFIRMED: loi ha tang khac hoan toan
        voi "khong khai thac duoc".
        """
        res = self._get("/JSON/core/action/accessUrl/", url=url, followRedirects="true")

        # ZAP bao loi bang cap khoa code/message.
        if "code" in res and "message" in res:
            raise ConnectionError(
                f"ZAP khong truy cap duoc {url}: {res['code']} - {res['message']}. "
                f"Kiem tra app co dang chay va co bind 0.0.0.0 khong."
            )

        # Thanh cong: {"accessUrl": [{... responseHeader ...}]}
        entries = res.get("accessUrl") or []
        if not entries:
            raise ConnectionError(f"ZAP tra ve phan hoi la cho {url}: {str(res)[:200]}")

        header = entries[0].get("responseHeader", "")
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})", header)
        if m:
            status = int(m.group(1))
            if status >= 400:
                raise ConnectionError(f"App tra ve HTTP {status} cho {url}")

    def active_scan(self, url: str, retries: int = 2) -> str:
        """Khoi tao active scan, thu lai khi ZAP tra ve 400.

        Vi sao can thu lai: accessUrl tra ve ngay sau khi gui yeu cau, nhung
        ZAP dung nut trong Sites tree BAT DONG BO. Goi ascan ngay sau do co
        the roi vao khoang thoi gian nut chua ton tai, va ZAP tu choi bang
        400 Bad Request. Day la mot cuoc dua ve thoi diem, khong phai loi
        logic: cung mot lenh, lan chay #2 tren runner GitHub thua cuoc dua,
        lan #4 thang.

        Thu lai o day la hop le vi 400 la mot LOI GOI HAM, khong phai mot
        ket qua kiem thu. No khong noi gi ve viec endpoint co lo hong hay
        khong. Neu het luot thu ma van 400 thi loi duoc nem ra va canh bao
        giu nhan UNCONFIRMED kem ly do - khong bao gio bi coi la an toan.
        """
        last_err: Exception | None = None
        for attempt in range(retries + 1):
            try:
                res = self._get(
                    "/JSON/ascan/action/scan/",
                    url=url,
                    recurse="false",
                    inScopeOnly="false",
                    method="GET",
                )
                return res.get("scan", "")
            except Exception as exc:  # noqa: BLE001 - can bat moi loi de thu lai
                last_err = exc
                if "400" not in str(exc) or attempt == retries:
                    raise
                # Danh thuc lai nut trong Sites tree roi cho no kip hinh thanh
                print(f"\n    -> ZAP tra 400, cho Sites tree roi thu lai "
                      f"(lan {attempt + 1}/{retries})", flush=True)
                try:
                    self.access_url(url)
                except Exception:
                    pass
                time.sleep(2 + attempt * 2)
        raise last_err  # type: ignore[misc]

    def wait(self, scan_id: str, progress: bool = False) -> None:
        deadline = time.time() + self.timeout
        last = -1
        while time.time() < deadline:
            status = self._get("/JSON/ascan/view/status/", scanId=scan_id).get("status", "0")
            if progress and status != last:
                print(f" {status}%", end="", flush=True)
                last = status
            if status == "100":
                return
            time.sleep(2)
        raise TimeoutError(f"ZAP scan {scan_id} qua {self.timeout}s chua xong")

    def alerts(self, baseurl: str) -> list[dict]:
        res = self._get("/JSON/core/view/alerts/", baseurl=baseurl, start="0", count="9999")
        return res.get("alerts", [])


def confirm_with_zap(zap: Zap, base_url: str, route: dict, param: str, cwe: str,
                     min_confidence: str) -> tuple[bool, str]:
    """Ban payload vao dung (URL, tham so) va doc alert tra ve."""
    cwe_num = cwe.split("-")[-1]
    seed = seed_for(route, param)
    target = f"{base_url}{route['url_path']}?{urlencode({param: seed})}"

    started = time.time()
    print(f"    -> accessUrl {target}", flush=True)
    zap.access_url(target)

    scan_id = zap.active_scan(target)
    if not scan_id:
        return False, "ZAP khong khoi tao duoc scan"

    print(f"    -> active scan id={scan_id}, dang quet", end="", flush=True)
    zap.wait(scan_id, progress=True)
    print(f" xong sau {time.time() - started:.0f}s", flush=True)

    floor = CONFIDENCE_RANK.get(min_confidence.lower(), 2)
    for a in zap.alerts(f"{base_url}{route['url_path']}"):
        if str(a.get("cweid")) != cwe_num:
            continue
        if a.get("param") and a.get("param") != param:
            continue
        if CONFIDENCE_RANK.get(str(a.get("confidence", "")).lower(), 0) < floor:
            continue
        return True, f"{a.get('alert')} (confidence={a.get('confidence')})"
    return False, "ZAP khong khai thac duoc trong pham vi policy hien tai"


# --------------------------------------------------------------------------
# Chuong trinh chinh
# --------------------------------------------------------------------------
SARIF_LEVEL = {CONFIRMED: "error", UNCONFIRMED: "warning", FILTERED: "note"}


def write_sarif(results: list[dict], path: Path) -> None:
    """
    Xuat ket qua DA GAN NHAN ra SARIF de day len GitHub Code Scanning.

    Khac voi SARIF tho cua Semgrep, file nay mang ket qua sau khi tuong quan:
      CONFIRMED   -> error   (chan build)
      UNCONFIRMED -> warning (cho review tay)
      FILTERED    -> note + suppressions, kem ly do loai tru

    Dung `suppressions` thay vi xoa han canh bao la co y: nguoi doc van thay
    canh bao ton tai va thay VI SAO no bi loai, thay vi no bien mat khong dau vet.
    """
    rules, seen = [], set()
    for r in results:
        rid = r["rule_id"] or "vulnshop-unknown"
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": r["message"][:120] or rid},
            "properties": {"tags": ["security", r["cwe"]]},
        })

    sarif_results = []
    for r in results:
        entry = {
            "ruleId": r["rule_id"] or "vulnshop-unknown",
            "level": SARIF_LEVEL[r["label"]],
            "message": {"text": f"[{r['label']}] {r['cwe']} tai {r['url'] or '?'} "
                                f"(tham so: {r['param'] or '-'}). {r['evidence']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": r["file"]},
                    "region": {"startLine": max(1, r["line"])},
                }
            }],
            "properties": {"label": r["label"], "cwe": r["cwe"]},
        }
        if r["label"] == FILTERED:
            entry["suppressions"] = [{
                "kind": "external",
                "justification": f"Loai tru bang bang chung tinh: {r['evidence']}",
            }]
        sarif_results.append(entry)

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "vulnshop-correlator",
                "semanticVersion": "1.0.0",
                "informationUri": "https://github.com/",
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default="reports/semgrep.sarif")
    ap.add_argument("--sanitizers", default="reports/sanitizers.sarif")
    ap.add_argument("--routes", default="routes_map.json")
    ap.add_argument("--out", default="reports/findings.json")
    ap.add_argument("--sarif-out", default="reports/correlated.sarif",
                    help="SARIF da gan nhan, de day len GitHub Code Scanning")
    ap.add_argument("--zap", default="http://localhost:8090", help="dia chi ZAP daemon")
    ap.add_argument("--zap-api-key", default="")
    ap.add_argument("--base-url", default="", help="URL app ma ZAP nhin thay")
    ap.add_argument("--min-confidence", default="medium")
    ap.add_argument("--scan-timeout", type=int, default=180,
                    help="so giay toi da cho moi lan ZAP active scan")
    ap.add_argument("--dry-run", action="store_true",
                    help="Bo qua ZAP. Chi kiem tra anh xa va FILTERED.")
    ap.add_argument("--no-tune", action="store_true",
                    help="Khong tu chinh scanner, dung nguyen policy mac dinh cua ZAP "
                         "(dung cho nghiem thuc doi chung B1)")
    ap.add_argument("--fail-on-unverified", action="store_true",
                    help="That bai khi co canh bao tinh nam tren endpoint kiem thu "
                         "duoc nhung chua he duoc hoi ZAP - tuc la rui ro da biet "
                         "ma khong ai kiem chung")
    ap.add_argument("--fail-on-confirmed", action="store_true",
                    help="Quality gate: thoat ma 1 neu co nhan CONFIRMED")
    ap.add_argument("--baseline-sarif", default="",
                    help="SARIF do Semgrep xuat voi --baseline-commit: chi chua canh bao "
                         "MOI so voi nhanh goc. Co tep nay thi cong chi chan phan moi; "
                         "no cu van duoc bao cao day du nhung khong chan merge.")
    args = ap.parse_args()

    findings = load_sarif_results(Path(args.findings))

    # ---- Baseline: canh bao nao la MOI so voi nhanh goc? -------------------
    #
    # Khong co buoc nay thi mot repo co san lo hong tu truoc se do vinh vien:
    # moi PR deu bi chan boi loi cua nguoi khac viet nam ngoai, va cach duy
    # nhat de lam viec tiep la tat han cong - tuc la mat luon cai co che nay
    # sinh ra de bao ve. Do la ly do so mot khien cac doi bo SAST sau mot tuan.
    #
    # Cach lam: quet TOAN BO va bao cao TOAN BO, nhung chi CHAN phan moi.
    # Baseline ap o cong, KHONG ap o luc quet. Dung --baseline-commit ngay tu
    # buoc Semgrep thi no cu bien mat khoi bao cao - lai la im lang bi trinh
    # bay thanh sach.
    #
    # Fail-closed: khong co tep baseline (chay tay, quet dinh ky, buoc baseline
    # hong) thi coi MOI canh bao la moi. Khong biet cai nao cu thi chan het,
    # chu khong phai bo qua het.
    moi_keys: set | None = None
    if args.baseline_sarif:
        bl = Path(args.baseline_sarif)
        if bl.is_file():
            moi_keys = {(r["rule_id"], r["file"], r["line"])
                        for r in load_sarif_results(bl)}
            print(f"[*] Baseline: {len(moi_keys)} canh bao MOI so voi nhanh goc "
                  f"(trong tong {len(findings)}). Cong chi chan phan moi.")
        else:
            print(f"[!] Khong co tep baseline {bl} - coi TAT CA canh bao la moi. "
                  f"Chat hon, khong long hon.")
    for f in findings:
        f["moi"] = True if moi_keys is None else \
            (f["rule_id"], f["file"], f["line"]) in moi_keys

    # Tep sanitizer la TUY CHON. Quet mot repo la bang bo rule cong dong thi
    # khong co no. Thieu thi khong co bang chung loai tru, nghia la khong co
    # nhan FILTERED - dung voi nguyen tac: khong co bang chung thi khong ket
    # luan, chu khong phai bia ra mot ket luan cho de.
    san_path = Path(args.sanitizers)
    if san_path.exists():
        sanitizers = load_sarif_results(san_path)
    else:
        sanitizers = []
        print(f"[!] Khong co {san_path} - bo qua buoc loc tinh, "
              f"se khong co nhan FILTERED.")

    routes_doc = json.loads(Path(args.routes).read_text(encoding="utf-8"))
    routes = routes_doc["routes"]
    base_url = args.base_url or routes_doc.get("app_base_url", "http://localhost:5000")

    zap = None
    if not args.dry_run:
        zap = Zap(args.zap, args.zap_api_key, timeout=args.scan_timeout)
        print(f"[*] ZAP phien ban {zap.ping()} | app tai {base_url}")
        print(f"[*] {len(findings)} canh bao SAST can xu ly. "
              f"Moi URL toi da {args.scan_timeout}s.")

        # Day la cho the hien ro nhat viec DAST duoc SAST dan huong: ho rule
        # ung voi CWE thuc su xuat hien trong ket qua SAST duoc day len muc
        # HIGH/LOW, tuc la ZAP thu nhieu payload hon va bao ca khi chua that
        # chac o dung nhung cho dang ngo.
        #
        # NOI CHO DUNG: buoc nay chi BAT THEM, khong tat rule nao. Cac rule
        # con lai trong policy mac dinh van chay binh thuong. Dan huong o day
        # nghia la "uu tien", khong phai "chi quet nhung cho nay".
        if not args.no_tune:
            wanted = {f["cwe"] for f in findings}
            for cwe in sorted(wanted):
                if cwe not in CWE_ZAP_SCANNER:
                    continue
                tuned = zap.tune_scanners(cwe)
                nhan = CWE_ZAP_SCANNER[cwe]["ten"]
                print(f"[*] {cwe} ({nhan}): da bat {len(tuned)} rule o muc HIGH/LOW")
                for t in tuned:
                    print(f"      - {t}")
                if not tuned:
                    print("      (!) ZAP khong co rule nao mang ma CWE nay. "
                          "Co the thieu addon beta/alpha.")

            ngoai_bang = sorted(c for c in wanted
                                if c not in CWE_ZAP_SCANNER and c != "UNKNOWN")
            if ngoai_bang:
                print(f"[*] {len(ngoai_bang)} ma CWE khong co active scan rule "
                      f"trong ZAP: {', '.join(ngoai_bang)}")
                print("    Cac canh bao nay se khong duoc hoi ZAP va khong tinh "
                      "vao cong chan.")
        print(flush=True)

    results = []
    for f in findings:
        # da_hoi_zap phan biet "hoi roi, ZAP khong thay gi" voi "chua he hoi".
        # Hai cai nay cung ra nhan UNCONFIRMED nhung y nghia nguoc nhau, va
        # chinh cho nay la lo hong: gop lam mot thi "khong kiem tra duoc" di
        # qua cong y het "da kiem tra va sach".
        # co_scanner: ZAP CO active scan rule cho ma CWE nay hay khong.
        # Phan biet "chua ai kiem tra" voi "khong co cong cu de kiem tra".
        # Thieu phan biet nay thi mot canh bao CWE-502 (deserialization) - ma
        # ZAP khong he co rule tuong ung - se lam do cong vinh vien, va khong
        # co cach nao sua ngoai viec tat cong di.
        row = dict(f, label=UNCONFIRMED, url=None, param=None, evidence="",
                   da_hoi_zap=False,
                   co_scanner=f["cwe"] in CWE_ZAP_SCANNER)

        route = find_route(f["file"], f["line"], routes)
        if route is None:
            row["evidence"] = "Khong anh xa duoc sang route nao"
            results.append(row)
            continue

        row["url"] = f"{base_url}{route['url_path']}"
        row["param"] = route["params"][0] if route["params"] else None

        # 1) Bang chung tinh loai tru -> FILTERED
        san = has_sanitizer_evidence(route, f["cwe"], sanitizers)
        if san:
            row["label"] = FILTERED
            row["evidence"] = f"Sanitizer tai dong {san['line']}: {san['message']}"
            results.append(row)
            continue

        # 2) Khong co tham so thi khong ban payload duoc
        if not row["param"]:
            row["evidence"] = "Action khong nhan tham so GET nao de kiem thu"
            results.append(row)
            continue

        # 3) ZAP khong co active scan rule cho loai lo hong nay
        #
        # Day la mot su that TINH ve nang luc cong cu, biet truoc khi chay, va
        # no la mot cau tra loi thuc su - khac han su im lang. Canh bao dung lai
        # o UNCONFIRMED nhung KHONG tinh vao cong chan, vi khong co hanh dong
        # nao lam no thanh CONFIRMED duoc ca.
        if not row["co_scanner"]:
            row["evidence"] = (f"ZAP khong co active scan rule cho {f['cwe']} "
                               f"- khong kiem chung dong duoc")
            results.append(row)
            continue

        # 4) Nho ZAP xac nhan
        if args.dry_run:
            row["evidence"] = "dry-run: chua goi ZAP"
        else:
            print(f"[>] Kiem thu {f['cwe']} tai {route['url_path']}"
                  f"?{row['param']}={seed_for(route, row['param'])}", flush=True)
            try:
                ok, detail = confirm_with_zap(
                    zap, base_url, route, row["param"], f["cwe"], args.min_confidence
                )
                row["label"] = CONFIRMED if ok else UNCONFIRMED
                row["evidence"] = detail
                row["da_hoi_zap"] = True   # ZAP tra loi that, du la tra loi "khong"
                print(f"    => {row['label']}: {detail}", flush=True)
            except Exception as exc:  # loi ha tang khong duoc bien thanh "an toan"
                row["evidence"] = f"Loi khi goi ZAP: {exc}"
                print(f"    => LOI: {exc}", flush=True)
        results.append(row)

    # ---- In bang ket qua ----
    width = max((len(r["url"] or "") for r in results), default=20) + 2
    print()
    co_baseline = moi_keys is not None
    tieu_de_moi = f"{'MOI?':<6}" if co_baseline else ""
    print(f"{'NHAN':<13}{'CWE':<9}{'URL':<{width}}{'PARAM':<8}"
          f"{tieu_de_moi}BANG CHUNG")
    print("-" * (34 + width + 40))
    for r in sorted(results, key=lambda x: (x["label"], not x.get("moi", True))):
        cot_moi = ("moi   " if r.get("moi", True) else "no cu ") if co_baseline else ""
        print(f"{r['label']:<13}{r['cwe']:<9}{(r['url'] or '-'):<{width}}"
              f"{(r['param'] or '-'):<8}{cot_moi}{r['evidence'][:52]}")

    tally = {lbl: sum(1 for r in results if r["label"] == lbl)
             for lbl in (CONFIRMED, UNCONFIRMED, FILTERED)}
    total = len(results) or 1
    resolved = (tally[CONFIRMED] + tally[FILTERED]) / total

    confirmed_moi = [r for r in results if r["label"] == CONFIRMED and r.get("moi", True)]
    confirmed_cu = [r for r in results if r["label"] == CONFIRMED and not r.get("moi", True)]

    # Rui ro DA BIET ma CHUA AI KIEM CHUNG: co canh bao tinh, ANH XA duoc sang
    # mot endpoint co tham so, khong co bang chung khu doc, va chua he hoi ZAP.
    # Day khong phai "chua co bang chung theo chieu nao" chung chung - day la
    # "dang le kiem tra duoc, nhung khong ai kiem tra".
    chua_kiem_chung = [r for r in results
                       if r["label"] == UNCONFIRMED and r.get("url")
                       and r.get("param") and not r.get("da_hoi_zap")
                       and r.get("co_scanner")]

    # Ngoai tam kiem thu dong: ZAP khong co active scan rule cho ma CWE do.
    # Tach rieng khoi nhom tren vi day KHONG phai no kiem thu - khong ai co the
    # tra duoc mon no nay bang cach bat them tang dong. Gop chung lam mot se
    # bien cong chan thanh cai khong bao gio qua noi, va ket cuc la nguoi ta tat
    # han no di - dung cai ket qua ma co che nay sinh ra de tranh.
    ngoai_tam_dast = [r for r in results
                      if r["label"] == UNCONFIRMED and not r.get("co_scanner")
                      and r["cwe"] != "UNKNOWN"]

    # Chi phan MOI moi tinh vao cong. No cu van nam trong bang tren, van vao
    # findings.json va SARIF, chi la khong chan merge cua nguoi khong gay ra no.
    chua_kiem_chung_moi = [r for r in chua_kiem_chung if r.get("moi", True)]

    # ---- Canh bao vs vi tri --------------------------------------------------
    # Mot dong ma co the bi HAI rule cung bat (rule du an + rule cong dong cung
    # chi vao mot cho). Do la hai canh bao, nhung chi MOT lo hong. Bao cao phai
    # noi ca hai con so, neu khong "6 CONFIRMED" se bi doc thanh 6 lo hong trong
    # khi ground truth co 4. Vi tri = (tep, dong, CWE).
    def vi_tri(rows: list[dict]) -> set:
        return {(r["file"], r["line"], r["cwe"]) for r in rows}

    tally_vt = {lbl: len(vi_tri([r for r in results if r["label"] == lbl]))
                for lbl in (CONFIRMED, UNCONFIRMED, FILTERED)}
    vt_moi = vi_tri(confirmed_moi)
    vt_cu = vi_tri(confirmed_cu)

    def so(lbl: str) -> str:
        """'4' neu canh bao = vi tri, '6 canh bao / 4 vi tri' neu khac."""
        n, v = tally[lbl], tally_vt[lbl]
        return f"{n}" if n == v else f"{n} canh bao / {v} vi tri"

    def gom(rows: list[dict]) -> list[tuple]:
        """Gop cac dong cung vi tri, dem so rule da bat - de in danh sach khong lap."""
        d: dict[tuple, dict] = {}
        for r in rows:
            k = (r["file"], r["line"], r["cwe"])
            if k not in d:
                d[k] = dict(r, so_rule=0)
            d[k]["so_rule"] += 1
        return sorted(d.values(), key=lambda x: (x["file"], x["line"]))

    print()
    print(f"Tong canh bao SAST : {len(results)}")
    if co_baseline:
        print(f"  CONFIRMED       : {so(CONFIRMED)}   "
              f"({len(vt_moi)} vi tri moi so voi nhanh goc, {len(vt_cu)} vi tri no cu)")
    else:
        print(f"  CONFIRMED       : {so(CONFIRMED)}")
    print(f"  FILTERED        : {so(FILTERED)}")
    print(f"  UNCONFIRMED     : {so(UNCONFIRMED)}   <- con lai cho review tay")
    print(f"Ti le phan giai tu dong: {resolved:.0%}  (tinh theo canh bao)")
    if chua_kiem_chung:
        print(f"  Trong so do, {len(vi_tri(chua_kiem_chung))} vi tri "
              f"({len(chua_kiem_chung)} canh bao) nam tren endpoint kiem thu duoc")
        print("  nhung CHUA HE duoc hoi ZAP:")
        for r in gom(chua_kiem_chung):
            nhan_rule = f"  ({r['so_rule']} rule)" if r["so_rule"] > 1 else ""
            print(f"      {r['cwe']:<9}{r['file']}:{r['line']}  ->  "
                  f"{r['url']}?{r['param']}={nhan_rule}")
    if ngoai_tam_dast:
        nhom = sorted({r["cwe"] for r in ngoai_tam_dast})
        print(f"  Va {len(ngoai_tam_dast)} canh bao NGOAI TAM kiem thu dong "
              f"({', '.join(nhom)}):")
        print("  ZAP khong co active scan rule cho nhung ma CWE nay, nen chung")
        print("  khong tinh vao cong chan. Phai review tay - khong co duong tu dong.")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"summary": tally,
                    "locations": tally_vt,
                    "resolution_rate": round(resolved, 4),
                    "unverified_testable": len(chua_kiem_chung),
                    "unverified_testable_new": len(chua_kiem_chung_moi),
                    "outside_dast_scope": len(ngoai_tam_dast),
                    "baseline_used": co_baseline,
                    "confirmed_new": len(confirmed_moi),
                    "confirmed_old": len(confirmed_cu),
                    "confirmed_new_locations": len(vt_moi),
                    "confirmed_old_locations": len(vt_cu),
                    "results": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nDa ghi {out}")

    if args.sarif_out:
        sarif_path = Path(args.sarif_out)
        write_sarif(results, sarif_path)
        print(f"Da ghi {sarif_path}")

    # ---- Cong chan -----------------------------------------------------------
    # Co baseline: chi chan phan MOI. No cu duoc in ra ngay duoi de khong ai
    # tuong la no da het - no chi khong chan merge cua nguoi khong gay ra no.
    # Danh sach in theo VI TRI, khong lap - mot dong bi hai rule bat thi in mot
    # lan kem "(2 rule)".
    chu_moi = "MOI " if co_baseline else ""

    def in_vi_tri(rows: list[dict]) -> None:
        for r in gom(rows):
            nhan_rule = f"  ({r['so_rule']} rule)" if r["so_rule"] > 1 else ""
            print(f"      {r['cwe']:<9}{r['file']}:{r['line']}  ->  "
                  f"{r['url']}?{r['param']}={nhan_rule}")

    if args.fail_on_confirmed and confirmed_moi:
        print(f"\n[QUALITY GATE] That bai: {len(vt_moi)} lo hong {chu_moi}da duoc "
              f"xac nhan khai thac duoc ({len(confirmed_moi)} canh bao).")
        in_vi_tri(confirmed_moi)
        if confirmed_cu:
            print(f"  (Ngoai ra con {len(vt_cu)} lo hong CONFIRMED cu tu truoc - "
                  f"khong chan lan nay, nhung van con do.)")
        return 1

    if args.fail_on_confirmed and confirmed_cu and not confirmed_moi:
        print(f"\n[QUALITY GATE] Qua. Lan thay doi nay KHONG them lo hong moi.")
        print(f"  Nhung {len(vt_cu)} lo hong CONFIRMED cu van con ({len(confirmed_cu)} "
              f"canh bao) - day la no ky thuat da biet, khong phai bang chung an toan.")
        in_vi_tri(confirmed_cu)

    if args.fail_on_unverified and chua_kiem_chung_moi:
        print(f"\n[QUALITY GATE] That bai: {len(chua_kiem_chung_moi)} canh bao tinh {chu_moi}"
              f"nam tren endpoint kiem thu duoc")
        print("nhung khong lan nao duoc hoi ZAP. Day la rui ro DA BIET ma CHUA AI")
        print("KIEM CHUNG - khong phai bang chung an toan.")
        print("Xu ly: bat tang dong len, hoac ghi nhan ngoai le co ly do.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
