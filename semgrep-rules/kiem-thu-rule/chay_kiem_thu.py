#!/usr/bin/env python3
"""
Kiem thu bo rule Semgrep cua du an.

VI SAO CAN TEP NAY
Mot rule chua chay thu thi chua phai la rule - no chi la mot y dinh viet bang
YAML. Rule co the sai cu phap, sai ten API, hoac dung mot dang pattern ma
Semgrep im lang khong khop. Ca ba truong hop deu ra cung mot ket qua: quet
xong, khong bao gi, va nguoi doc tuong la ma nguon sach.

Tep nay bien dieu do thanh mot cau hoi tra loi duoc.

BA DIEU KIEN DUOC KIEM TRA
  1. Moi rule PHAT HIEN phai bat duoc it nhat mot case trong Co_Loi.*
     -> that bai nghia la rule do mu, khong bao ve gi ca
  2. KHONG rule phat hien nao duoc bat trong Da_Khu_Doc.cs
     -> that bai nghia la rule bao nham ma nguon da khu doc (duong tinh gia)
  3. Moi rule SANITIZER phai bat duoc bang chung trong Da_Khu_Doc.cs
     -> that bai nghia la khong co nhan FILTERED nao sinh ra duoc

CACH CHAY
    python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py

Can Docker Desktop dang chay, hoac semgrep cai san trong PATH.
Ma tra ve 0 neu dat ca ba dieu kien, 1 neu khong.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

THU_MUC = Path(__file__).resolve().parent
RULES = THU_MUC.parent
TEP_PHAT_HIEN = RULES / "sast-detect.yaml"
TEP_SANITIZER = RULES / "sanitizer-check.yaml"
TEP_AN_TOAN = "Da_Khu_Doc.cs"

ID_RE = re.compile(r"^\s*-\s*id:\s*(\S+)\s*$", re.M)


def doc_id_rule(tep: Path) -> list[str]:
    """Lay danh sach id rule tu mot tep YAML, khong can thu vien ngoai."""
    if not tep.is_file():
        raise SystemExit(f"Khong tim thay {tep}")
    return ID_RE.findall(tep.read_text(encoding="utf-8"))


def chay_semgrep(out: Path) -> None:
    """Chay Semgrep tren thu muc fixture, xuat JSON ra `out`.

    Uu tien semgrep cai san; khong co thi dung Docker giong phan con lai cua
    bo cong cu. Khong co ca hai thi bao ro rang - KHONG duoc im lang bo qua
    roi bao "dat", vi khong chay duoc khac hoan toan voi chay xong khong loi.
    """
    cau_hinh = [f"--config={TEP_PHAT_HIEN}", f"--config={TEP_SANITIZER}"]

    if shutil.which("semgrep"):
        lenh = ["semgrep", "scan", *cau_hinh, str(THU_MUC),
                "--json", "--output", str(out), "--metrics=off", "--quiet"]
        subprocess.run(lenh, check=False, encoding="utf-8", errors="replace")
        return

    if not shutil.which("docker"):
        raise SystemExit(
            "Khong tim thay semgrep lan docker.\n"
            "  - Bat Docker Desktop len, hoac\n"
            "  - pip install semgrep"
        )

    lenh = [
        "docker", "run", "--rm",
        "-v", f"{THU_MUC}:/fixture:ro",
        "-v", f"{RULES}:/rules:ro",
        "-v", f"{out.parent}:/out",
        "-w", "/fixture", "semgrep/semgrep", "semgrep", "scan",
        "--config=/rules/sast-detect.yaml",
        "--config=/rules/sanitizer-check.yaml",
        ".", "--json", "--output", f"/out/{out.name}",
        "--metrics=off", "--quiet",
    ]
    kq = subprocess.run(lenh, capture_output=True, text=True,
                        encoding="utf-8", errors="replace")
    if not out.is_file():
        chi_tiet = (kq.stderr or kq.stdout or "").strip()
        goi_y = ""
        if "docker.sock" in chi_tiet or "daemon" in chi_tiet.lower():
            goi_y = "\nDocker Desktop chua chay. Mo no len roi chay lai."
        raise SystemExit(
            f"Semgrep khong xuat duoc ket qua (docker tra ve {kq.returncode}).\n"
            f"{chi_tiet[:800]}{goi_y}"
        )


def main() -> int:
    id_phat_hien = doc_id_rule(TEP_PHAT_HIEN)
    id_sanitizer = doc_id_rule(TEP_SANITIZER)
    print(f"[*] {len(id_phat_hien)} rule phat hien, "
          f"{len(id_sanitizer)} rule sanitizer")
    print("[*] Dang chay Semgrep tren fixture ...\n")

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "kq.json"
        chay_semgrep(out)
        data = json.loads(out.read_text(encoding="utf-8"))

    # Gom ket qua theo (id rule -> tap tep da bat)
    trung: dict[str, set[str]] = {}
    for r in data.get("results", []):
        rid = r.get("check_id", "").split(".")[-1]
        trung.setdefault(rid, set()).add(Path(r.get("path", "")).name)

    hong: list[str] = []

    # --- Dieu kien 1: moi rule phat hien phai bat duoc case cua no ----------
    print("DIEU KIEN 1 - rule phat hien co bat duoc case co loi khong")
    print("-" * 68)
    for rid in id_phat_hien:
        tep = trung.get(rid, set())
        co_loi = {t for t in tep if t != TEP_AN_TOAN}
        if co_loi:
            print(f"  DAT     {rid:<45} {', '.join(sorted(co_loi))}")
        else:
            print(f"  HONG    {rid:<45} khong bat duoc gi")
            hong.append(f"rule phat hien mu: {rid}")

    # --- Dieu kien 2: khong duoc bat nham ma nguon da khu doc ---------------
    print("\nDIEU KIEN 2 - co bao nham ma nguon da khu doc khong")
    print("-" * 68)
    bao_nham = [rid for rid in id_phat_hien if TEP_AN_TOAN in trung.get(rid, set())]
    if bao_nham:
        for rid in bao_nham:
            print(f"  HONG    {rid:<45} bat nham {TEP_AN_TOAN}")
            hong.append(f"duong tinh gia: {rid}")
    else:
        print(f"  DAT     khong rule nao bat nham {TEP_AN_TOAN}")

    # --- Dieu kien 3: sanitizer phai tim duoc bang chung --------------------
    print("\nDIEU KIEN 3 - rule sanitizer co tim duoc bang chung khu doc khong")
    print("-" * 68)
    for rid in id_sanitizer:
        if TEP_AN_TOAN in trung.get(rid, set()):
            print(f"  DAT     {rid}")
        else:
            print(f"  HONG    {rid:<45} khong tim thay bang chung")
            hong.append(f"sanitizer mu: {rid}")

    print("\n" + "=" * 68)
    if hong:
        print(f"KIEM THU THAT BAI - {len(hong)} van de:")
        for h in hong:
            print(f"  - {h}")
        print("\nRule hong thi lo hong tuong ung di qua pipeline ma khong ai biet.")
        return 1

    print(f"KIEM THU DAT - {len(id_phat_hien)} rule phat hien va "
          f"{len(id_sanitizer)} rule sanitizer deu hoat dong dung.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
