#!/usr/bin/env python3
"""
Cong chan o may lap trinh vien: quet cac tep SAP COMMIT, truoc khi commit xong.

Day la mat xich dau tien trong chuoi bon cong cua do an:
    IDE  ->  PRE-COMMIT  ->  Pull Request (CI)  ->  Quet dinh ky

Vi sao can mat xich nay du da co CI: CI chay SAU khi ma nguon da roi khoi may.
Vong phan hoi dai hon (day len, cho runner, doc log), va neu lo hong lot vao
lich su git thi go ra rat phien - nhat la voi bi mat bi lo, vi xoa tep o commit
sau khong xoa duoc no khoi cac commit truoc.

Nguyen tac thiet ke - phai NHANH, neu khong nguoi ta se tat no di:
  * Chi quet tep dang trong staging area, khong quet ca repo.
  * Chi dung rule cuc bo cua do an, khong tai bo rule cong dong qua mang.
  * Chi chan khi muc do la ERROR. Muc thap hon thi canh bao roi cho di tiep,
    de nguoi dung khong bi chan vi mot canh bao khong chac chan.

Cai dat (chay mot lan tai thu muc goc cua repo):
    python tools/pre_commit_scan.py --install

Go ra:
    python tools/pre_commit_scan.py --uninstall

Bo qua mot lan khi that su can:
    git commit --no-verify
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "semgrep-rules"
EXTS = {".cs", ".cshtml", ".razor", ".sql", ".json", ".yml", ".yaml", ".config"}

# Thu muc fixture kiem thu rule chua ma CO LOI CO Y. Phai loai tru, neu khong
# hook se chan chinh commit cua bo cong cu nay. Day khong phai ngoai le cho
# tien - fixture la du lieu kiem thu, khong phai ma nguon ung dung.
BO_QUA = ("semgrep-rules/kiem-thu-rule/",)

HOOK = """#!/bin/sh
# Sinh boi tools/pre_commit_scan.py - go bang: python tools/pre_commit_scan.py --uninstall
exec "{python}" "{script}" --run
"""


def repo_goc() -> Path:
    """Goc cua repo DANG COMMIT - khong nhat thiet la goc cua bo cong cu.

    Hai duong dan nay truoc day bi gop lam mot, va hook chi chay dung khi ban
    commit ngay trong repo chua bo cong cu. Lam viec o du an khac thi semgrep
    duoc dua cho danh sach tep tuong doi so voi du an do, nhung lai chay voi
    thu muc goc la bo cong cu - khong tep nao ton tai, khong canh bao nao hien
    ra, va hook bao "khong co loi". Im lang bi trinh bay thanh an toan, dung
    cai loi ca do an nay dat ra de tranh.
    """
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    if out.returncode != 0:
        raise SystemExit("Khong phai thu muc git.")
    return Path(out.stdout.strip())


def staged_files() -> list[str]:
    """Cac tep dang cho commit, bo qua tep da xoa."""
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return [f for f in out.stdout.splitlines()
            if f.strip() and Path(f).suffix.lower() in EXTS
            and not f.replace("\\", "/").startswith(BO_QUA)]


def run_semgrep(files: list[str]) -> tuple[bool, list[dict]]:
    """Quet bang rule cuc bo.

    Tra ve (da_quet_duoc, ket_qua). Phai phan biet hai truong hop, vi chung
    khac nhau hoan toan ve y nghia:
        (True,  [])  - da quet, khong thay gi
        (False, [])  - KHONG quet duoc, khong biet gi ca
    Gop hai cai nay lam mot la dung "im lang" lam "bang chung an toan" - dung
    cai loi ma ca do an nay dat ra de tranh. Ban dau chinh script nay mac loi
    do: Docker khong chay, khong co ket qua, va no bao "khong co loi".
    """
    if not RULES.is_dir():
        print(f"  Khong tim thay {RULES}.")
        return False, []

    tmp = Path(tempfile.mkdtemp()) / "out.json"
    src = repo_goc()          # repo dang commit
    if shutil.which("semgrep"):
        cmd = ["semgrep", "scan", f"--config={RULES}", "--json",
               "--output", str(tmp), "--metrics=off", "--quiet", *files]
    elif shutil.which("docker"):
        # Hai mount tach bach: /src la ma nguon dang commit, /rules la bo rule
        # cua bo cong cu. Gop lam mot thi hook chi chay dung o dung mot repo.
        cmd = ["docker", "run", "--rm",
               "-v", f"{src}:/src:ro",
               "-v", f"{RULES}:/rules:ro",
               "-v", f"{tmp.parent}:/out", "-w", "/src", "semgrep/semgrep",
               "semgrep", "scan", "--config=/rules", "--json",
               "--output", "/out/out.json", "--metrics=off", "--quiet", *files]
    else:
        print("  Khong tim thay semgrep lan docker.")
        return False, []

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=180, cwd=src)
    except subprocess.TimeoutExpired:
        print("  Qua 180 giay, bo do.")
        return False, []

    if not tmp.exists():
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        print("  " + (err[-1][:160] if err else "semgrep khong tao duoc ket qua"))
        return False, []

    return True, json.loads(tmp.read_text(encoding="utf-8")).get("results", [])


def do_run() -> int:
    files = staged_files()
    if not files:
        return 0

    print(f"[pre-commit] quet {len(files)} tep dang commit ...")
    scanned, results = run_semgrep(files)

    if not scanned:
        print("[pre-commit] KHONG QUET DUOC - cho commit di tiep, nhung luu y:")
        print("             day khong phai ket luan ma nguon sach, chi la chua kiem tra.")
        print("             CI se quet lai khi ban mo pull request.")
        return 0

    blockers, warnings = [], []
    for r in results:
        sev = (r.get("extra", {}).get("severity") or "").upper()
        item = (r.get("path", ""), r.get("start", {}).get("line", 0),
                r.get("check_id", "").split(".")[-1],
                (r.get("extra", {}).get("message") or "").strip().split("\n")[0])
        (blockers if sev == "ERROR" else warnings).append(item)

    for path, line, rule, msg in warnings:
        print(f"  canh bao  {path}:{line}  {msg[:90]}")

    if not blockers:
        print(f"[pre-commit] da quet, khong co loi muc ERROR trong "
              f"{len(files)} tep nay. Cho commit di tiep.")
        return 0

    print("\n" + "=" * 68)
    print(f"COMMIT BI CHAN - {len(blockers)} loi muc ERROR trong phan ban vua sua:")
    print("=" * 68)
    for path, line, rule, msg in blockers:
        print(f"\n  {path}:{line}")
        print(f"    {msg}")
        print(f"    rule: {rule}")
    print("\n" + "-" * 68)
    print("Sua roi commit lai. Neu chac chan day la duong tinh gia, them chu thich")
    print("  // nosemgrep: <ten-rule>")
    print("ngay tren dong do - cach nay de lai dau vet trong ma nguon, khac voi")
    print("`git commit --no-verify` la bo qua am tham khong ai biet.")
    return 1


def hook_path() -> Path:
    out = subprocess.run(["git", "rev-parse", "--git-dir"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    if out.returncode != 0:
        raise SystemExit("Khong phai thu muc git.")
    return Path(out.stdout.strip()) / "hooks" / "pre-commit"


def do_install() -> int:
    p = hook_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(HOOK.format(python=sys.executable.replace("\\", "/"),
                             script=str(Path(__file__).resolve()).replace("\\", "/")),
                 encoding="utf-8")
    os.chmod(p, 0o755)
    print(f"Da cai hook tai {p}")
    print("Tu gio moi lan `git commit` se quet cac tep dang commit truoc.")
    return 0


def do_uninstall() -> int:
    p = hook_path()
    if p.exists():
        p.unlink()
        print(f"Da go {p}")
    else:
        print("Khong co hook nao de go.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--install", action="store_true")
    g.add_argument("--uninstall", action="store_true")
    g.add_argument("--run", action="store_true", help="hook goi vao day")
    args = ap.parse_args()

    if args.install:
        return do_install()
    if args.uninstall:
        return do_uninstall()
    return do_run()


if __name__ == "__main__":
    raise SystemExit(main())
