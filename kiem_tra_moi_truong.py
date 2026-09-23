"""Kiem tra MOT LAN tat ca dieu kien can cho buoi demo.

Khong phai mot phan cua do an. Day la script chan doan dung mot lan roi xoa.
Muc dich: thay vi chay quet - hong - sua - chay lai bay vong, script nay hoi
het moi cau hoi cung luc va in ra mot bang duy nhat.

Chay:  python kiem_tra_moi_truong.py

Chi dung thu vien chuan, khong can pip install gi.
In ra ASCII thuan de khong dinh loi bang ma tren console Windows.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ZAP = "http://localhost:8090"
APP_PORT = 5000
ROOT = Path(__file__).resolve().parent

rows: list[tuple[str, bool, str, str]] = []   # (ten, dat/khong, chi tiet, cach sua)


def add(name: str, ok: bool, detail: str, fix: str = "") -> None:
    rows.append((name, ok, detail, fix))


def http_get(url: str, timeout: float = 6.0) -> tuple[int, str]:
    """Tra ve (ma HTTP, than phan hoi). Ma 0 nghia la khong ket noi duoc."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


# --------------------------------------------------------------------------
# 1. Python
# --------------------------------------------------------------------------
v = sys.version_info
add("Python", v >= (3, 9), f"{v.major}.{v.minor}.{v.micro}", "Can Python 3.9 tro len")


# --------------------------------------------------------------------------
# 2. Docker
# --------------------------------------------------------------------------
if not shutil.which("docker"):
    add("Docker", False, "khong tim thay lenh docker", "Cai Docker Desktop")
else:
    p = subprocess.run(["docker", "info"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=20)
    add("Docker daemon", p.returncode == 0,
        "dang chay" if p.returncode == 0 else "co lenh docker nhung daemon chua len",
        "Mo Docker Desktop va cho no khoi dong xong")


# --------------------------------------------------------------------------
# 3. Container ZAP - co dang chay khong, mo cong nao
# --------------------------------------------------------------------------
if shutil.which("docker"):
    p = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=20)
    zap_line = ""
    for line in (p.stdout or "").splitlines():
        if line.lower().startswith("zap"):
            zap_line = line.strip()
    if zap_line:
        ok8090 = "8090" in zap_line
        add("Container ZAP", ok8090, zap_line,
            "Cong phai la 8090. Chay lai:\n"
            "       docker rm -f zap\n"
            "       docker run -d --name zap -p 8090:8090 zaproxy/zap-stable "
            "zap.sh -daemon -host 0.0.0.0 -port 8090 "
            "-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true "
            "-config api.disablekey=true")
    else:
        add("Container ZAP", False, "khong thay container nao ten zap dang chay",
            "docker run -d --name zap -p 8090:8090 zaproxy/zap-stable "
            "zap.sh -daemon -host 0.0.0.0 -port 8090 "
            "-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true "
            "-config api.disablekey=true")


# --------------------------------------------------------------------------
# 4. API cua ZAP co tra loi khong
# --------------------------------------------------------------------------
code, body = http_get(f"{ZAP}/JSON/core/view/version/")
zap_up = code == 200
detail = f"phien ban {json.loads(body).get('version')}" if zap_up else body[:110]
add("API ZAP o cong 8090", zap_up, detail,
    "ZAP can 20-40 giay moi san sang sau khi docker run. Cho roi chay lai script nay.")


# --------------------------------------------------------------------------
# 5. Ung dung VulnShop nhin tu CHINH MAY NAY
# --------------------------------------------------------------------------
host_urls = [f"http://localhost:{APP_PORT}",
             f"http://127.0.0.1:{APP_PORT}",
             f"http://host.docker.internal:{APP_PORT}"]
reachable = []
for u in host_urls:
    c, _ = http_get(u, timeout=4)
    if c:
        reachable.append(u)
add("VulnShop nhin tu may nay", bool(reachable),
    ("phan hoi tai: " + ", ".join(reachable)) if reachable
    else "khong dia chi nao phan hoi",
    "Mo mot cua so terminal rieng trong thu muc VulnShop va chay:\n"
    "       dotnet run --urls http://localhost:5000")

# Rieng cai ten host.docker.internal co phan giai duoc tu Windows khong
hdi_ok = f"http://host.docker.internal:{APP_PORT}" in reachable
if reachable:
    add("Ten host.docker.internal tren Windows", hdi_ok,
        "phan giai duoc" if hdi_ok
        else "Windows khong phan giai duoc ten nay (khong sao, ZAP van dung duoc)",
        "" if hdi_ok else "Khong can sua. Ban va da xu ly truong hop nay.")


# --------------------------------------------------------------------------
# 6. Cau hoi quan trong nhat: ZAP co voi toi ung dung khong
# --------------------------------------------------------------------------
# Day la phep thu duy nhat co y nghia cho tang 4. Bon phep thu tren deu hoi
# tu may that; phep thu nay bao ZAP tu di goi, tuc la hoi dung cai may se
# thuc su ban payload.
if zap_up:
    best = ""
    for target in (f"http://host.docker.internal:{APP_PORT}",
                   f"http://localhost:{APP_PORT}"):
        q = urllib.parse.urlencode({"url": target, "followRedirects": "true"})
        c, b = http_get(f"{ZAP}/JSON/core/action/accessUrl/?{q}", timeout=25)
        if c == 200:
            best = target
            break
    add("ZAP voi toi VulnShop", bool(best),
        f"ZAP truy cap duoc {best}" if best
        else "ZAP khong truy cap duoc ca host.docker.internal lan localhost",
        "" if best else
        "ZAP nam trong container nen localhost cua no la chinh no.\n"
        "       Neu host.docker.internal cung hong, chay ZAP bang:\n"
        "       docker run -d --name zap --add-host=host.docker.internal:host-gateway "
        "-p 8090:8090 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8090 "
        "-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true "
        "-config api.disablekey=true")
    if best:
        add("URL can dien vao o URL ung dung", True, best, "")


# --------------------------------------------------------------------------
# 7. Bo rule rieng cua do an
# --------------------------------------------------------------------------
for f, why in (("semgrep-rules/sast-detect.yaml", "thieu file nay thi chay rule cong dong, mat nhan CWE"),
               ("semgrep-rules/sanitizer-check.yaml", "thieu file nay thi khong bao gio co nhan FILTERED")):
    p = ROOT / f
    add(f, p.is_file(), "co" if p.is_file() else "khong thay", why)


# --------------------------------------------------------------------------
# 8. Tep ket qua cu con sot lai
# --------------------------------------------------------------------------
reports = ROOT / "reports"
stale = sorted(p.name for p in reports.glob("*VulnShop*")) if reports.is_dir() else []
add("Tep ket qua cu cua VulnShop", True,
    f"{len(stale)} tep - webui.py se tu xoa truoc khi quet" if stale else "khong co",
    "")


# --------------------------------------------------------------------------
# In bang
# --------------------------------------------------------------------------
w = max(len(r[0]) for r in rows) + 2
print()
print("=" * (w + 60))
print("KIEM TRA MOI TRUONG DEMO - VulnShop")
print("=" * (w + 60))
for name, ok, detail, _ in rows:
    print(f"  [{('OK' if ok else 'HONG'):<4}]  {name.ljust(w)}{detail}")

fails = [r for r in rows if not r[1] and r[3]]
print()
if not fails:
    print("Tat ca deu dat. Mo dashboard va bam quet:")
    print("       python tools\\webui.py")
else:
    print(f"Co {len(fails)} viec can sua, theo thu tu:")
    print()
    for i, (name, _, _, fix) in enumerate(fails, 1):
        print(f"  {i}. {name}")
        for line in fix.splitlines():
            print(f"     {line}")
        print()
print("=" * (w + 60))
