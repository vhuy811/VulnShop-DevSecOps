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

# Tu khoa de tim active scan rule cua ZAP ung voi tung CWE.
# Dung ten thay vi id cung vi tap rule thay doi theo phien ban va addon cai dat.
CWE_SCANNER_KEYWORD = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross Site Scripting",
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
        for res in run.get("results", []):
            msg = res.get("message", {}).get("text", "")
            loc = res.get("locations", [{}])[0]
            phys = loc.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)

            m = CWE_RE.search(msg)
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

    def tune_scanners(self, keyword: str, strength: str = "HIGH",
                      threshold: str = "LOW") -> list[str]:
        """
        Bat va tang do nhay cac active scan rule co ten khop `keyword`.

        Vi sao can: policy mac dinh cua ZAP chay o cuong do MEDIUM va nguong
        canh bao MEDIUM. O muc do, ZAP thu it payload va chi bao khi rat chac,
        nen lo hong co that van co the khong bi phat hien. Pipeline tu cau hinh
        scanner theo CWE cua canh bao SAST se sat muc tieu hon nhieu.

        Tra ve danh sach rule da chinh de ghi vao bao cao (tai lap duoc).
        """
        scanners = self._get("/JSON/ascan/view/scanners/").get("scanners", [])
        tuned = []
        for s in scanners:
            name = s.get("name", "")
            if keyword.lower() not in name.lower():
                continue
            sid = s.get("id")
            try:
                self._get("/JSON/ascan/action/enableScanners/", ids=sid)
                self._get("/JSON/ascan/action/setScannerAttackStrength/",
                          id=sid, attackStrength=strength)
                self._get("/JSON/ascan/action/setScannerAlertThreshold/",
                          id=sid, alertThreshold=threshold)
                tuned.append(f"{sid} {name}")
            except Exception as exc:
                print(f"    (!) Khong chinh duoc rule {sid} {name}: {exc}")
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
    ap.add_argument("--fail-on-confirmed", action="store_true",
                    help="Quality gate: thoat ma 1 neu co nhan CONFIRMED")
    args = ap.parse_args()

    findings = load_sarif_results(Path(args.findings))

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

        # Chi bat nhung rule tuong ung voi CWE thuc su xuat hien trong ket qua SAST.
        # Day la cho the hien ro nhat viec DAST duoc SAST dan huong: khong quet
        # bua, chi bat dung ho rule can thiet.
        if not args.no_tune:
            wanted = {f["cwe"] for f in findings}
            for cwe, keyword in CWE_SCANNER_KEYWORD.items():
                if cwe in wanted:
                    tuned = zap.tune_scanners(keyword)
                    print(f"[*] {cwe}: da bat {len(tuned)} rule o muc HIGH/LOW")
                    for t in tuned:
                        print(f"      - {t}")
        print(flush=True)

    results = []
    for f in findings:
        row = dict(f, label=UNCONFIRMED, url=None, param=None, evidence="")

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

        # 3) Nho ZAP xac nhan
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
                print(f"    => {row['label']}: {detail}", flush=True)
            except Exception as exc:  # loi ha tang khong duoc bien thanh "an toan"
                row["evidence"] = f"Loi khi goi ZAP: {exc}"
                print(f"    => LOI: {exc}", flush=True)
        results.append(row)

    # ---- In bang ket qua ----
    width = max((len(r["url"] or "") for r in results), default=20) + 2
    print()
    print(f"{'NHAN':<13}{'CWE':<9}{'URL':<{width}}{'PARAM':<8}BANG CHUNG")
    print("-" * (34 + width + 40))
    for r in sorted(results, key=lambda x: x["label"]):
        print(f"{r['label']:<13}{r['cwe']:<9}{(r['url'] or '-'):<{width}}"
              f"{(r['param'] or '-'):<8}{r['evidence'][:52]}")

    tally = {lbl: sum(1 for r in results if r["label"] == lbl)
             for lbl in (CONFIRMED, UNCONFIRMED, FILTERED)}
    total = len(results) or 1
    resolved = (tally[CONFIRMED] + tally[FILTERED]) / total

    print()
    print(f"Tong canh bao SAST : {len(results)}")
    print(f"  CONFIRMED       : {tally[CONFIRMED]}")
    print(f"  FILTERED        : {tally[FILTERED]}")
    print(f"  UNCONFIRMED     : {tally[UNCONFIRMED]}   <- con lai cho review tay")
    print(f"Ti le phan giai tu dong: {resolved:.0%}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"summary": tally, "resolution_rate": round(resolved, 4),
                    "results": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nDa ghi {out}")

    if args.sarif_out:
        sarif_path = Path(args.sarif_out)
        write_sarif(results, sarif_path)
        print(f"Da ghi {sarif_path}")

    if args.fail_on_confirmed and tally[CONFIRMED] > 0:
        print(f"\n[QUALITY GATE] That bai: {tally[CONFIRMED]} lo hong da duoc xac nhan.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
