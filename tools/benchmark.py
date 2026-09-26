#!/usr/bin/env python3
"""
Do va so sanh ba nghiem thuc quet dong.

    B1 - Quet mu        : ZAP spider toan bo ung dung roi active scan nhung gi tim duoc.
                          Day la cach dung ZAP khi khong co thong tin nao tu ma nguon.
    B2 - Biet endpoint  : ZAP duoc cho san danh sach MOI endpoint co tham so (lay tu
                          routes_map.json) roi quet tat ca. Bo qua han che cua spider,
                          nhung van khong biet endpoint nao dang nghi ngo.
    B3 - Co chu dich    : chi quet nhung (URL, tham so) ma SAST chi ra, sau khi da loai
                          bo cac canh bao co bang chung tinh loai tru (nhan FILTERED).

Vi sao can ca B2: neu chi so B1 voi B3 thi mot nguoi phan bien se noi "B1 thua chi
vi spider kem, khong lien quan gi den SAST". B2 cat bo lap luan do - no cho ZAP
biet dung nhung endpoint ma B3 biet, nen khac biet con lai giua B2 va B3 chi con la
PHAM VI quet, dung dieu can do.

Ca ba nghiem thuc:
  - deu bat dau bang MOT PHIEN ZAP MOI (khong lam vay thi alert va tai cua lan truoc
    do don sang lan sau, lam sai ca thoi gian lan ket qua),
  - deu dung cung cau hinh scanner (HIGH/LOW, cung tap rule),
nen khac biet duy nhat giua chung la quet cai gi.

Cach dung:
    python tools/benchmark.py --base-url http://host.docker.internal:5000 --runs 1
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).parent))
from correlate import CWE_ZAP_SCANNER, Zap, seed_for  # noqa: E402


class BenchZap(Zap):
    """Them may thao tac ZAP chi dung cho phep do."""

    def new_session(self) -> None:
        self._get("/JSON/core/action/newSession/", name="", overwrite="true")

    def spider(self, url: str) -> str:
        return self._get("/JSON/spider/action/scan/", url=url, recurse="true").get("scan", "")

    def spider_wait(self, scan_id: str) -> None:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if self._get("/JSON/spider/view/status/", scanId=scan_id).get("status") == "100":
                return
            time.sleep(1)
        raise TimeoutError("Spider qua han")

    def ascan_recursive(self, url: str) -> str:
        return self._get("/JSON/ascan/action/scan/", url=url,
                         recurse="true", inScopeOnly="false").get("scan", "")

    def all_urls(self) -> list[str]:
        return self._get("/JSON/core/view/urls/").get("urls", [])


def reset(zap: BenchZap, base_url: str) -> None:
    """
    Phien moi + cau hinh scanner giong het nhau cho moi nghiem thuc.

    Sau newSession cay Sites bi xoa sach. ZAP tu choi active scan mot URL
    chua co trong cay do, nen phai truy cap trang goc de tao lai node truoc
    khi quet bat cu thu gi.
    """
    zap.new_session()
    for cwe in CWE_ZAP_SCANNER:
        zap.tune_scanners(cwe)
    time.sleep(2)  # de ZAP on dinh sau khi doi phien
    zap.access_url(base_url + "/")
    time.sleep(1)


def collect_hits(zap: BenchZap, base_url: str) -> list[dict]:
    """
    Lay chi tiet alert thuoc hai CWE dang xet.

    Tra ve chi tiet chu khong chi dem, vi con so tong khong tra loi duoc cau
    hoi quan trong: mot lo hong bi bao nhieu lan, va co alert nao roi vao
    endpoint von an toan hay khong.
    """
    out = []
    for a in zap.alerts(base_url):
        if str(a.get("cweid")) not in ("79", "89"):
            continue
        url = a.get("url", "")
        out.append({
            "endpoint": url.split("?")[0].replace(base_url, "") or "/",
            "param": a.get("param", ""),
            "rule": a.get("alert", ""),
            "cwe": f"CWE-{a.get('cweid')}",
            "confidence": a.get("confidence", ""),
        })
    return out


def summarise_hits(hits: list[dict]) -> None:
    """In bang phan ra: moi endpoint bi bao bao nhieu alert, boi rule nao."""
    if not hits:
        print("     (khong co alert nao thuoc CWE-79/89)")
        return
    by_ep: dict[str, list[dict]] = {}
    for h in hits:
        by_ep.setdefault(h["endpoint"], []).append(h)
    print(f"     Phan ra {len(hits)} alert tren {len(by_ep)} endpoint:")
    for ep, group in sorted(by_ep.items()):
        rules = ", ".join(sorted({g["rule"] for g in group}))
        params = ", ".join(sorted({g["param"] for g in group if g["param"]}))
        print(f"       {ep:<24} x{len(group):<3} param={params or '-':<8} {rules}")


# --------------------------------------------------------------------------
def run_b1_spider(zap: BenchZap, base_url: str) -> dict:
    reset(zap, base_url)
    t0 = time.time()

    zap.access_url(f"{base_url}/Product/List")
    zap.spider_wait(zap.spider(base_url))
    n_urls = len(zap.all_urls())
    zap.wait(zap.ascan_recursive(base_url), progress=True)

    elapsed = time.time() - t0
    print()
    hits = collect_hits(zap, base_url)
    return {"seconds": elapsed, "urls_scanned": n_urls,
            "vulns_found": len(hits), "hits": hits}


def run_b2_seeded(zap: BenchZap, base_url: str, routes: list[dict]) -> dict:
    """Cho ZAP biet truoc moi endpoint co tham so, roi quet tat ca."""
    reset(zap, base_url)
    targets = [r for r in routes if r.get("params")]
    t0 = time.time()

    for r in targets:
        param = r["params"][0]
        url = f"{base_url}{r['url_path']}?{urlencode({param: seed_for(r, param)})}"
        zap.access_url(url)
        zap.wait(zap.active_scan(url))
        print(".", end="", flush=True)

    elapsed = time.time() - t0
    print()
    hits = collect_hits(zap, base_url)
    return {"seconds": elapsed, "urls_scanned": len(targets),
            "vulns_found": len(hits), "hits": hits}


def run_b3_guided(zap: BenchZap, base_url: str, zap_endpoint: str,
                  scan_timeout: int) -> dict:
    """Chay correlate.py tren mot phien sach."""
    reset(zap, base_url)
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, "tools/correlate.py",
         "--zap", zap_endpoint, "--base-url", base_url,
         "--scan-timeout", str(scan_timeout), "--no-tune"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    elapsed = time.time() - t0
    if proc.returncode not in (0, 1):  # 1 la quality gate, khong phai loi
        print(proc.stdout[-1500:])
        print(proc.stderr[-1500:])
        raise RuntimeError(f"correlate.py that bai, ma thoat {proc.returncode}")

    data = json.loads(Path("reports/findings.json").read_text(encoding="utf-8"))
    s = data["summary"]
    return {
        "seconds": elapsed,
        "urls_scanned": s["CONFIRMED"] + s["UNCONFIRMED"],  # so URL that su ban payload
        "vulns_found": s["CONFIRMED"],
        "filtered": s["FILTERED"],
        "unconfirmed": s["UNCONFIRMED"],
        "resolution_rate": data["resolution_rate"],
    }


# --------------------------------------------------------------------------
def stat(runs: list[dict], key: str) -> tuple[float, float]:
    vals = [r[key] for r in runs]
    return statistics.mean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zap", default="http://localhost:8090")
    ap.add_argument("--base-url", default="http://host.docker.internal:5000")
    ap.add_argument("--routes", default="routes_map.json")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--scan-timeout", type=int, default=240,
                    help="gioi han cho MOT active scan nham vao mot URL (B2, B3)")
    ap.add_argument("--b1-timeout", type=int, default=900,
                    help="gioi han cho lan quet de quy toan bo ung dung cua B1. "
                         "Phai lon hon nhieu so voi --scan-timeout vi B1 quet ca "
                         "site trong mot lan chu khong tung URL mot")
    ap.add_argument("--out", default="reports/benchmark.json")
    ap.add_argument("--only", default="B1,B2,B3",
                    help="chi chay mot so nghiem thuc, vi du --only B2")
    args = ap.parse_args()
    chosen = {k.strip().upper() for k in args.only.split(",")}

    routes = json.loads(Path(args.routes).read_text(encoding="utf-8"))["routes"]
    zap = BenchZap(args.zap, timeout=args.scan_timeout)
    print(f"[*] ZAP {zap.ping()} | app {args.base_url} | {args.runs} lan moi nghiem thuc")
    print(f"[*] Gioi han moi active scan: {args.scan_timeout}s\n")

    acc: dict[str, list[dict]] = {"B1": [], "B2": [], "B3": []}

    def attempt(key: str, title: str, fn, budget: int) -> None:
        """
        Chay mot nghiem thuc. Mot nghiem thuc hong KHONG duoc keo sap ca phep do:
        ghi lai la that bai roi di tiep, vi hai nghiem thuc con lai van co gia tri.
        """
        if key not in chosen:
            return
        print(f"[{key}] {title}")
        zap.timeout = budget
        t0 = time.time()
        try:
            r = fn()
        except Exception as exc:
            elapsed = time.time() - t0
            print(f"     THAT BAI sau {elapsed:.0f}s: {exc}\n")
            acc[key].append({"seconds": elapsed, "urls_scanned": 0,
                             "vulns_found": 0, "failed": str(exc)})
            return
        extra = ""
        if key == "B3":
            extra = (f", {r['filtered']} FILTERED, {r['unconfirmed']} UNCONFIRMED")
        print(f"     {r['seconds']:.0f}s | {r['urls_scanned']} URL "
              f"| {r['vulns_found']} lo hong{extra}")
        if r.get("hits"):
            summarise_hits(r["hits"])
        print()
        acc[key].append(r)

    for i in range(1, args.runs + 1):
        print(f"=== Lan {i}/{args.runs} ===")
        attempt("B1", "Quet mu - spider roi quet tat ca",
                lambda: run_b1_spider(zap, args.base_url), args.b1_timeout)
        attempt("B2", "Biet endpoint - quet moi endpoint co tham so",
                lambda: run_b2_seeded(zap, args.base_url, routes), args.scan_timeout)
        attempt("B3", "Co chu dich - chi quet cho SAST chi ra",
                lambda: run_b3_guided(zap, args.base_url, args.zap, args.scan_timeout),
                args.scan_timeout)

    labels = {"B1": "Quet mu (spider)", "B2": "Biet endpoint",
              "B3": "Co chu dich (SAST)"}
    print("=" * 74)
    print(f"{'Nghiem thuc':<24}{'Thoi gian':<20}{'URL quet':<12}{'Lo hong tim duoc'}")
    print("-" * 74)
    for k in ("B1", "B2", "B3"):
        if not acc[k]:
            continue
        m, sd = stat(acc[k], "seconds")
        mu, _ = stat(acc[k], "urls_scanned")
        mv, _ = stat(acc[k], "vulns_found")
        t = f"{m:.0f}s +/- {sd:.0f}s" if args.runs > 1 else f"{m:.0f}s"
        note = "  (THAT BAI)" if any("failed" in r for r in acc[k]) else ""
        print(f"{k} {labels[k]:<21}{t:<20}{mu:<12.0f}{mv:.0f}/4{note}")
    print("=" * 74)

    print("\nCach doc ket qua:")
    print("  B1 so B2 : spider co tim ra duoc endpoint co tham so hay khong.")
    print("  B2 so B3 : cung biet endpoint, khac nhau o cho co thu hep pham vi")
    print("             theo chi dan SAST hay khong.")
    print("\nKhong duoc ket luan B3 'tot hon' mot cach chung chung: B3 co tran do phu")
    print("bi chan boi SAST, nen no khong thay the B1/B2 ma bo sung cho chung.")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(acc, indent=2), encoding="utf-8")
    print(f"\nDa ghi {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
