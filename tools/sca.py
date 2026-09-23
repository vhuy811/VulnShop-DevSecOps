#!/usr/bin/env python3
"""
Tang SCA - quet thu vien, doi chieu voi co so du lieu lo hong da cong bo.

Khac biet can ban so voi SAST/DAST:
  - SAST doan theo HINH DANG code, co the doan sai.
  - DAST doan theo HANH VI phan hoi, cung co the doan sai.
  - SCA KHONG doan. No so phien ban thu vien voi GitHub Advisory Database
    (anh xa sang CVE). Trung thi trung, khong trung thi thoi. Khong co
    duong tinh gia theo nghia cua hai tang kia.

Vi vay ket qua cua tang nay luon mang nhan CONFIRMED: su ton tai cua thu
vien dinh loi la su that kiem chung duoc, khong phai suy doan.

Cau hoi con lai - "lo hong do co CHAM toi duoc trong ung dung nay khong" -
la cau hoi khac, va cong cu nay khong tra loi duoc. Xem ghi chu reachability
o cuoi file.

Chay doc lap:
    python tools/sca.py --repo ../eShopOnWeb
    python tools/sca.py --from-file ket_qua.txt      # phan tich output co san
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT = re.compile(r"^Project\s+[`'\"](?P<name>[^`'\"]+)[`'\"]\s+has the following vulnerable")
HEADER = re.compile(r"^\s*(?P<kind>Top-level|Transitive)\s+Package\b")
# > Ten   [Requested]   Resolved   Severity   URL
PKG = re.compile(
    r"^\s*>\s+(?P<name>\S+)\s+(?P<versions>[\d][^\s]*(?:\s+[\d][^\s]*)?)\s+"
    r"(?P<sev>Critical|High|Moderate|Low)\s+(?P<url>\S+)"
)
# dong tiep: chi co Severity + URL, thuoc ve goi ngay tren
EXTRA = re.compile(r"^\s+(?P<sev>Critical|High|Moderate|Low)\s+(?P<url>\S+)\s*$")

SEV_RANK = {"Critical": 4, "High": 3, "Moderate": 2, "Low": 1}
# Du an test khong chay tren production - can tach ra khi xep uu tien
TEST_HINT = re.compile(r"(UnitTests?|IntegrationTests?|FunctionalTests?|\.Tests?)$", re.I)


def parse(text: str) -> list[dict]:
    """Phan tich output cua `dotnet list package --vulnerable`."""
    findings: list[dict] = []
    project, kind, last = None, None, None

    for line in text.splitlines():
        m = PROJECT.match(line)
        if m:
            project, kind, last = m.group("name"), None, None
            continue

        m = HEADER.match(line)
        if m:
            kind = m.group("kind").lower().replace("-level", "")
            last = None
            continue

        m = PKG.match(line)
        if m and project:
            vs = m.group("versions").split()
            last = {
                "project": project,
                "package": m.group("name"),
                "version": vs[-1],
                "dependency": kind or "unknown",
                "severity": m.group("sev"),
                "advisories": [m.group("url")],
                "is_test_project": bool(TEST_HINT.search(project)),
            }
            findings.append(last)
            continue

        m = EXTRA.match(line)
        if m and last is not None:
            last["advisories"].append(m.group("url"))
            # giu muc nghiem trong cao nhat trong cac advisory cua cung goi
            if SEV_RANK[m.group("sev")] > SEV_RANK[last["severity"]]:
                last["severity"] = m.group("sev")

    return findings


def run_dotnet(repo: Path) -> str:
    """Goi `dotnet list package --vulnerable` tren repo."""
    if not shutil.which("dotnet"):
        raise SystemExit("Khong tim thay lenh `dotnet`. Cai .NET SDK truoc.")

    slns = sorted(repo.glob("*.sln"))
    target = str(slns[0]) if slns else str(repo)

    print(f"[SCA] dotnet restore {Path(target).name} ...", flush=True)
    subprocess.run(["dotnet", "restore", target], cwd=repo,
                   capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)

    print(f"[SCA] dotnet list package --vulnerable ...", flush=True)
    proc = subprocess.run(
        ["dotnet", "list", target, "package", "--vulnerable", "--include-transitive"],
        cwd=repo, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900,
    )
    return proc.stdout + "\n" + proc.stderr


def dedupe(findings: list[dict]) -> list[dict]:
    """
    Gop cac ban ghi cua cung mot goi tu nhieu du an.

    Uu tien giu ban "top-level": mot goi khai bao truc tiep thi sua duoc
    ngay bang cach nang phien ban, con goi transitive thi phai doi thu vien
    cha cap nhat. Hai tinh huong nay hanh dong khac nhau nen khong duoc gop nham.
    """
    pkgs: dict[tuple, dict] = {}
    for f in findings:
        key = (f["package"], f["version"])
        cur = pkgs.get(key)
        if cur is None:
            pkgs[key] = dict(f)
            continue
        if f["dependency"] == "top" and cur["dependency"] != "top":
            cur["dependency"] = "top"
            cur["project"] = f["project"]
        if SEV_RANK[f["severity"]] > SEV_RANK[cur["severity"]]:
            cur["severity"] = f["severity"]
        for a in f["advisories"]:
            if a not in cur["advisories"]:
                cur["advisories"].append(a)
        # goi nao xuat hien o du an khong phai test thi tinh la production
        cur["is_test_project"] = cur["is_test_project"] and f["is_test_project"]
    return list(pkgs.values())


def summarise(findings: list[dict]) -> dict:
    pkgs = {(f["package"], f["version"]): f for f in dedupe(findings)}
    advisories = {a for f in findings for a in f["advisories"]}
    by_sev = {s: 0 for s in SEV_RANK}
    for f in pkgs.values():
        by_sev[f["severity"]] += 1
    transitive = sum(1 for f in pkgs.values() if f["dependency"] == "transitive")
    prod = {k: v for k, v in pkgs.items() if not v["is_test_project"]}
    return {
        "packages": len(pkgs),
        "advisories": len(advisories),
        "by_severity": by_sev,
        "transitive": transitive,
        "in_production_projects": len(prod),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="thu muc repo can quet")
    ap.add_argument("--from-file", help="phan tich output da luu san, khong goi dotnet")
    ap.add_argument("--out", default="reports/sca.json")
    args = ap.parse_args()

    if args.from_file:
        text = Path(args.from_file).read_text(encoding="utf-8", errors="replace")
    elif args.repo:
        text = run_dotnet(Path(args.repo).resolve())
    else:
        raise SystemExit("Can --repo hoac --from-file")

    findings = parse(text)
    s = summarise(findings)

    print()
    print(f"{'Goi':<40}{'Phien ban':<12}{'Muc do':<11}{'Nguon goc':<12}Advisory")
    print("-" * 96)
    for f in sorted(dedupe(findings), key=lambda x: (-SEV_RANK[x["severity"]], x["package"])):
        print(f"{f['package']:<40}{f['version']:<12}{f['severity']:<11}"
              f"{f['dependency']:<12}{len(f['advisories'])}")

    print()
    print(f"Goi dinh lo hong        : {s['packages']}")
    print(f"Advisory rieng biet     : {s['advisories']}")
    print(f"  Critical / High       : {s['by_severity']['Critical']} / {s['by_severity']['High']}")
    print(f"  Moderate / Low        : {s['by_severity']['Moderate']} / {s['by_severity']['Low']}")
    print(f"Goi transitive          : {s['transitive']}/{s['packages']}"
          f"  <- lap trinh vien khong chu dong chon, khong thay trong .csproj")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"summary": s, "findings": dedupe(findings)},
                              indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nDa ghi {out}")
    return 0


# GHI CHU VE REACHABILITY
# -----------------------
# Cong cu nay tra loi "thu vien dinh loi CO MAT trong du an khong".
# No KHONG tra loi "doan ma dinh loi co duoc GOI toi trong ung dung nay khong".
# Hai cau hoi khac nhau, giong het su khac nhau giua CONFIRMED va
# "true positive nhung khong khai thac duoc" o tang SAST/DAST.
# Phan tich reachability nam ngoai pham vi do an; cot `is_test_project`
# la mot xap xi tho: lo hong trong du an test khong chay tren production.

if __name__ == "__main__":
    sys.exit(main())
