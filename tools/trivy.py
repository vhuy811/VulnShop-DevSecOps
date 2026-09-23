#!/usr/bin/env python3
"""
Tang ha tang - quet container image, cau hinh trien khai, va sinh SBOM.

Vi sao tang nay can thiet: ba tang truoc (SCA, SAST, DAST) chi nhin thay MA NGUON
UNG DUNG. Nhung ung dung that khong chay tran tren may - no chay trong container,
tren mot he dieu hanh co hang tram goi rieng, cau hinh bang Dockerfile va manifest.
Phan do thuong chua NHIEU lo hong hon chinh ma nguon ung dung, va ba tang kia mu
hoan toan voi no.

Ba viec:
    image   - quet container image: goi he dieu hanh + thu vien ung dung
    config  - quet Dockerfile va manifest trien khai tim loi cau hinh
    sbom    - sinh danh muc thanh phan (CycloneDX), gio la yeu cau phap ly o EU va My

Cach dung:
    python tools/trivy.py --image vulnshop:naive
    python tools/trivy.py --config .
    python tools/trivy.py --sbom .
    python tools/trivy.py --compare          # dung 2 image roi so so CVE
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

TRIVY_IMAGE = "aquasec/trivy:latest"
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"


def need(cmd: str) -> None:
    if not shutil.which(cmd):
        raise SystemExit(f"Khong tim thay lenh `{cmd}`. Cai truoc khi chay.")


def trivy(args: list[str], mounts: list[str] | None = None,
          fmt: str = "json", timeout: int = 1800) -> dict:
    """Goi Trivy qua Docker, tra ve JSON da phan tich."""
    need("docker")
    cmd = ["docker", "run", "--rm",
           "-v", "/var/run/docker.sock:/var/run/docker.sock",
           "-v", f"{Path.home() / '.cache' / 'trivy'}:/root/.cache/trivy"]
    for m in mounts or []:
        cmd += ["-v", m]
    cmd += [TRIVY_IMAGE] + args + ["--format", fmt, "--quiet"]

    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    out = proc.stdout.strip()
    if not out:
        raise SystemExit(f"Trivy khong tra ve gi.\n{proc.stderr[-600:]}")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # Tren Windows duong dan docker.sock khac; bao loi ro thay vi vo tay
        raise SystemExit(f"Khong doc duoc ket qua Trivy.\n{out[:400]}\n{proc.stderr[-400:]}")


# --------------------------------------------------------------------------
def scan_image(tag: str) -> dict:
    print(f"[Trivy] quet image {tag} ...", flush=True)
    doc = trivy(["image", tag, "--scanners", "vuln"])

    vulns, by_sev, by_class = [], Counter(), Counter()
    for res in doc.get("Results") or []:
        cls = res.get("Class", "?")
        for v in res.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            by_sev[sev] += 1
            by_class[cls] += 1
            vulns.append({
                "id": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion") or "",
                "severity": sev,
                "title": (v.get("Title") or "")[:140],
                "url": v.get("PrimaryURL") or "",
                "layer": "hệ điều hành" if cls == "os-pkgs" else "thư viện ứng dụng",
            })
    return {"target": tag, "total": len(vulns),
            "by_severity": dict(by_sev), "by_class": dict(by_class),
            "vulnerabilities": vulns}


def scan_config(path: str) -> dict:
    p = Path(path).resolve()
    print(f"[Trivy] quet cau hinh trong {p} ...", flush=True)
    doc = trivy(["config", "/target"], mounts=[f"{p}:/target:ro"])

    issues, by_sev = [], Counter()
    for res in doc.get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            sev = (m.get("Severity") or "UNKNOWN").upper()
            by_sev[sev] += 1
            issues.append({
                "id": m.get("ID"),
                "target": res.get("Target"),
                "line": (m.get("CauseMetadata") or {}).get("StartLine", 0),
                "severity": sev,
                "title": m.get("Title") or "",
                "message": (m.get("Message") or "")[:180],
                "fix": (m.get("Resolution") or "")[:180],
                "url": m.get("PrimaryURL") or "",
            })
    return {"target": str(p), "total": len(issues),
            "by_severity": dict(by_sev), "issues": issues}


def make_sbom(path: str, out: Path) -> dict:
    p = Path(path).resolve()
    print(f"[Trivy] sinh SBOM cho {p} ...", flush=True)
    doc = trivy(["fs", "/target"], mounts=[f"{p}:/target:ro"], fmt="cyclonedx")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    comps = doc.get("components") or []
    return {"components": len(comps), "file": out.name}


# --------------------------------------------------------------------------
def print_sev(by_sev: dict, indent: str = "  ") -> None:
    parts = [f"{s} {by_sev.get(s, 0)}" for s in SEV_ORDER if by_sev.get(s)]
    print(indent + ("  ".join(parts) if parts else "khong co"))


def build_and_compare() -> dict:
    """Dung ca hai Dockerfile roi so so CVE - phep do truoc/sau khi gia co."""
    need("docker")
    results = {}
    for tag, dockerfile in (("vulnshop:naive", "Dockerfile"),
                            ("vulnshop:hardened", "Dockerfile.hardened")):
        print(f"\n[Docker] build {tag} tu {dockerfile} ...", flush=True)
        proc = subprocess.run(
            ["docker", "build", "-f", str(ROOT / dockerfile), "-t", tag, str(ROOT)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
        if proc.returncode != 0:
            print(f"  Build that bai:\n{proc.stderr[-800:]}")
            continue
        results[tag] = scan_image(tag)
        print(f"  {results[tag]['total']} lo hong")
        print_sev(results[tag]["by_severity"], "    ")

    if len(results) == 2:
        a = results["vulnshop:naive"]
        b = results["vulnshop:hardened"]
        print("\n" + "=" * 62)
        print(f"{'':<22}{'Ngay tho':>14}{'Da gia co':>14}{'Giam':>12}")
        print("-" * 62)
        for s in SEV_ORDER:
            x, y = a["by_severity"].get(s, 0), b["by_severity"].get(s, 0)
            if x or y:
                print(f"{s:<22}{x:>14}{y:>14}{x - y:>12}")
        print(f"{'TONG':<22}{a['total']:>14}{b['total']:>14}{a['total'] - b['total']:>12}")
        if a["total"]:
            print(f"\nGiam {(a['total'] - b['total']) / a['total'] * 100:.0f}% so lo hong "
                  f"chi bang cach doi image nen va bo quyen root.")
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", help="tag image can quet")
    ap.add_argument("--config", help="thu muc chua Dockerfile / manifest")
    ap.add_argument("--sbom", help="thu muc sinh SBOM")
    ap.add_argument("--compare", action="store_true",
                    help="build ca hai Dockerfile roi so so CVE")
    ap.add_argument("--out-prefix", default="trivy")
    args = ap.parse_args()

    REPORTS.mkdir(exist_ok=True)
    result = {}

    if args.compare:
        result["compare"] = build_and_compare()

    if args.image:
        r = scan_image(args.image)
        result["image"] = r
        print(f"\n{r['total']} lo hong trong image")
        print_sev(r["by_severity"])
        print(f"  theo tang: {r['by_class']}")

    if args.config:
        r = scan_config(args.config)
        result["config"] = r
        print(f"\n{r['total']} loi cau hinh")
        print_sev(r["by_severity"])
        for i in sorted(r["issues"],
                        key=lambda x: SEV_ORDER.index(x["severity"]))[:12]:
            print(f"  [{i['severity']:<8}] {i['target']}:{i['line']}  {i['id']}  {i['title']}")
            if i["fix"]:
                print(f"             Sua: {i['fix'][:110]}")

    if args.sbom:
        r = make_sbom(args.sbom, REPORTS / f"{args.out_prefix}_sbom.json")
        result["sbom"] = r
        print(f"\nSBOM: {r['components']} thanh phan -> reports/{r['file']}")

    if not result:
        ap.print_help()
        return 1

    out = REPORTS / f"{args.out_prefix}.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nDa ghi {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
