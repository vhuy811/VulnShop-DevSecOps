#!/usr/bin/env python3
"""
Bang dieu khien demo - giao dien cuc bo cho toan bo quy trinh.

Ba the:
    Tong quan  - kien truc 5 tang, quy che 3 nhan, 4 cong cuong che
    Chay       - kiem tra moi truong roi chay tung tang, co trang thai ro rang
    Ket qua    - bang 3 nhan kem bang chung, va bao cao day du

Chi dung thu vien chuan cua Python - khong cai them gi.

NGUYEN TAC THIET KE: HONG MOT CACH RO RANG.
Moi tang tu kiem tra dieu kien cua no TRUOC khi chay. Khi khong chay duoc, no
ghi ro LY DO roi nhuong cho tang sau, thay vi lam sap ca lan quet. Khong bao gio
im lang bo qua - vi mot tang im lang de bi hieu nham thanh "da quet va sach".

Cach dung:
    python tools/webui.py
    (tu mo trinh duyet tai http://localhost:8000)
"""
from __future__ import annotations

import argparse
import html
import http.server
import json
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

JOBS: dict[str, dict] = {}
ZAP_URL = "http://localhost:8090"


# ==========================================================================
# Kiem tra moi truong truoc khi chay
# ==========================================================================
def http_ok(url: str, timeout: float = 3) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status < 400
    except Exception:
        return False


def docker_ready() -> tuple[bool, str]:
    """Docker co THUC SU dung duoc khong.

    shutil.which chi cho biet co LENH docker, khong cho biet daemon dang chay.
    Hai trang thai nay khac nhau ve y nghia: khong co lenh la "chua cai", con
    daemon chua chay la "cai roi nhung quen bat" - nguoi dung xu ly khac nhau.
    """
    if not shutil.which("docker"):
        return False, "khong tim thay lenh docker"
    try:
        if subprocess.run(["docker", "info"], capture_output=True,
                          timeout=8).returncode == 0:
            return True, "dang chay"
    except Exception:
        pass
    return False, "co lenh docker nhung daemon chua chay"


def short_err(*streams: str) -> str:
    """Dong loi cuoi cung co nghia, thay vi 160 ky tu cuoi cua ca khoi log.

    Cat theo ky tu lam cau bi chem dau dau: "I at unix:///var/run/docker.sock"
    - nguoi doc khong hieu gi. Lay nguyen mot dong thi con doc duoc.
    """
    for text in streams:
        lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
        if lines:
            return lines[-1][:170]
    return "khong ro ly do"


def host_probe_urls(base_url: str) -> list[str]:
    """Dia chi de CHINH MAY NAY thu xem app con song khong.

    base_url la dia chi ZAP nhin thay, thuong la host.docker.internal vi ZAP
    nam trong container. Nhung chinh may Windows co the khong phan giai duoc
    ten do, nen lay no di kiem tra "app con song khong" la hoi sai may.
    Ham nay chi suy ra dia chi tuong duong de THU, con dia chi giao cho ZAP
    van giu nguyen khong doi.
    """
    urls = [base_url]
    for alias in ("host.docker.internal", "gateway.docker.internal"):
        if alias in base_url:
            urls.append(base_url.replace(alias, "localhost"))
            urls.append(base_url.replace(alias, "127.0.0.1"))
    return urls


def app_alive(base_url: str) -> tuple[bool, str]:
    """True neu bat ky dia chi tuong duong nao phan hoi."""
    tried = host_probe_urls(base_url)
    for u in tried:
        if http_ok(u):
            return True, (f"{u} phan hoi" if u == base_url
                          else f"{u} phan hoi (may nay khong phan giai duoc "
                               f"ten trong {base_url}, nhung ZAP thi duoc)")
    return False, "khong dia chi nao phan hoi: " + ", ".join(tried)


def preflight(base_url: str = "") -> list[dict]:
    """Kiem tra tung dieu kien TRUOC khi quet.

    Ly do ton tai: mot buoi bao ve keo dai 15 phut. Phat hien Docker chua bat
    o phut thu 8, giua luc dang trinh bay, la mat trang. Bang nay cho biet cai
    gi san sang truoc khi bam nut.
    """
    out = [{"id": "python", "name": "Python", "ok": True,
            "detail": f"{sys.version_info.major}.{sys.version_info.minor}",
            "need": "bat buoc", "layers": "tat ca"}]

    dotnet = shutil.which("dotnet")
    out.append({"id": "dotnet", "name": ".NET SDK", "ok": bool(dotnet),
                "detail": "san sang" if dotnet else "khong tim thay lenh dotnet",
                "need": "can cho tang 1", "layers": "Thu vien (SCA)"})

    ok, why = docker_ready()
    out.append({"id": "docker", "name": "Docker", "ok": ok, "detail": why,
                "need": "can cho tang 2 va 3", "layers": "Ma nguon, Ha tang"})

    zap = http_ok(f"{ZAP_URL}/JSON/core/view/version/")
    out.append({"id": "zap", "name": "OWASP ZAP", "ok": zap,
                "detail": "dang lang nghe o cong 8090" if zap
                          else "khong ket noi duoc localhost:8090",
                "need": "can cho tang 4", "layers": "Doi sanh tinh x dong"})

    if base_url:
        app, detail = app_alive(base_url)
        out.append({"id": "app", "name": "Ung dung dich", "ok": app,
                    "detail": detail,
                    "need": "can cho tang 4", "layers": "Doi sanh tinh x dong"})
    return out


# ==========================================================================
# Dinh nghia cac tang - dung chung cho ca giao dien lan bo chay
# ==========================================================================
def new_stages(base_url: str, use_sast: bool, use_trivy: bool) -> list[dict]:
    def st(sid, name, tool, src, dst, active):
        return {"id": sid, "name": name, "tool": tool, "input": src,
                "output": dst, "state": "pending" if active else "skip",
                "detail": "" if active else "da tat trong tuy chon", "seconds": 0}

    return [
        st("sca", "Tầng 1 — Thư viện", "sca.py + dotnet",
           "*.csproj", "CVE", True),
        st("sast", "Tầng 2 — Mã nguồn", "Semgrep",
           "*.cs, *.cshtml", "CWE", use_sast),
        st("routes", "Tầng 3 — Bản đồ endpoint", "gen_routes_map.py",
           "Controller, Razor Pages", "(URL, tham số)", True),
        st("trivy", "Tầng 4 — Hạ tầng", "Trivy",
           "Dockerfile", "CVE + lỗi cấu hình", use_trivy),
        st("dast", "Tầng 5 — Đối sánh tĩnh × động", "correlate.py + ZAP",
           "SARIF + bản đồ + app đang chạy", "3 nhãn", bool(base_url)),
        st("report", "Dựng báo cáo", "report.py",
           "tất cả kết quả trên", "trang HTML", True),
    ]


# ==========================================================================
# Chay mot lan quet
# ==========================================================================
def run_scan(job_id: str, repo: str, title: str, use_sast: bool,
             base_url: str = "", use_trivy: bool = False) -> None:
    job = JOBS[job_id]
    stages = {s["id"]: s for s in job["stages"]}

    def log(msg: str, kind: str = "info") -> None:
        job["log"].append({"t": time.strftime("%H:%M:%S"), "m": msg, "k": kind})

    def begin(sid: str) -> float:
        stages[sid]["state"] = "running"
        job["step"] = stages[sid]["name"]
        return time.time()

    def done(sid: str, t0: float, state: str, detail: str) -> None:
        s = stages[sid]
        s["state"] = state
        s["detail"] = detail
        s["seconds"] = round(time.time() - t0, 1)
        log(f"{s['name']}: {detail}",
            {"ok": "ok", "skip": "warn", "fail": "err", "gate": "err"}.get(state, "info"))

    try:
        repo_path = Path(repo).expanduser().resolve()
        if not repo_path.is_dir():
            raise FileNotFoundError(f"Khong tim thay thu muc: {repo_path}")

        slug = "".join(c if c.isalnum() else "_" for c in title)[:40] or "target"
        f_sca = REPORTS / f"sca_{slug}.json"
        f_sast = REPORTS / f"sast_{slug}.sarif"
        f_san = REPORTS / f"sanitizers_{slug}.sarif"
        f_routes = REPORTS / f"routes_{slug}.json"
        f_dast = REPORTS / f"dast_{slug}.json"
        f_trivy = REPORTS / f"trivy_{slug}.json"
        f_html = REPORTS / f"bao_cao_{slug}.html"
        job["report"] = None

        # Xoa ket qua cu cung slug TRUOC khi quet.
        #
        # Khong lam viec nay thi mot tang bi skip (Docker tat, ZAP chua len)
        # se de lai tep cua lan chay truoc, va buoc dung bao cao thay tep do
        # van con nen dem vao nhu ket qua moi. Bao cao khi ay tron du lieu cua
        # hai lan chay khac nhau ma khong noi gi - dung dieu do an nay to cao:
        # trinh bay "khong co ket qua moi" nhu la "ket qua".
        # Xoa truoc thi tang bi skip se khong co tep, va bao cao bo han tang do.
        stale = [f_sca, f_sast, f_san, f_routes, f_dast, f_trivy, f_html,
                 REPORTS / f"correlated_{slug}.sarif"]
        wiped = 0
        for p in stale:
            if p.exists():
                p.unlink()
                wiped += 1
        if wiped:
            log(f"Da xoa {wiped} tep ket qua cu cua '{title}' de khong lan voi lan chay nay")

        log(f"Muc tieu: {repo_path}")

        # ---------------- Tang 1: thu vien ----------------
        t0 = begin("sca")
        if not shutil.which("dotnet"):
            done("sca", t0, "skip", "khong co .NET SDK — chua kiem tra thu vien")
        else:
            r = subprocess.run(
                [sys.executable, str(TOOLS / "sca.py"), "--repo", str(repo_path),
                 "--out", str(f_sca)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800, cwd=ROOT)
            if f_sca.exists():
                s = json.loads(f_sca.read_text(encoding="utf-8"))["summary"]
                done("sca", t0, "ok",
                     f"{s['packages']} gói dính CVE · Critical {s['by_severity']['Critical']}"
                     f" · High {s['by_severity']['High']} · {s['transitive']} gián tiếp")
            else:
                done("sca", t0, "fail", short_err(r.stderr, r.stdout))

        # ---------------- Tang 2: ma nguon ----------------
        t0 = begin("sast")
        if not use_sast:
            done("sast", t0, "skip", "đã tắt trong tuỳ chọn")
        elif not docker_ready()[0]:
            done("sast", t0, "skip",
                 f"{docker_ready()[1]} — chưa phân tích được mã nguồn")
        else:
            # Repo co bo rule rieng thi dung bo do, khong dung rule cong dong.
            #
            # Ly do quan trong: bo rule cua do an ghi ma CWE thang trong thong
            # diep ("CWE-89: ..."), con rule cong dong de CWE trong metadata.
            # Engine doi sanh doc CWE tu thong diep, nen dung rule cong dong thi
            # moi canh bao thanh CWE UNKNOWN va khong ghep duoc voi endpoint.
            # Quan trong hon: rule cong dong KHONG co bo kiem sanitizer, nen
            # khong bao gio sinh duoc nhan FILTERED - mat han mot phan ba cua
            # luoc do ba nhan.
            # Chon bo rule theo thu tu uu tien:
            #   1. Rule nam trong chinh repo dich  (repo tu mang rule cua no)
            #   2. Rule cua do an nay, mount vao container
            #      -> nho buoc nay moi quet duoc repo ben ngoai bang rule rieng.
            #         Rule cua do an la mau C# tong quat (noi chuoi vao
            #         CommandText, Html.Raw...), khong dinh gi rieng VulnShop.
            #   3. Rule cong dong p/csharp - phuong an cuoi
            tgt_rules = repo_path / "semgrep-rules"
            own_rules = ROOT / "semgrep-rules"
            if (tgt_rules / "sast-detect.yaml").is_file():
                rules_dir, nguon = tgt_rules, "bộ rule nằm trong repo đích"
            elif (own_rules / "sast-detect.yaml").is_file():
                rules_dir, nguon = own_rules, "bộ rule của đồ án"
            else:
                rules_dir, nguon = None, "bộ rule cộng đồng p/csharp"

            def semgrep(config: str, out_name: str) -> subprocess.CompletedProcess:
                cmd = ["docker", "run", "--rm",
                       "-v", f"{repo_path}:/src:ro", "-v", f"{REPORTS}:/out"]
                if rules_dir is not None:
                    cmd += ["-v", f"{rules_dir}:/rules:ro"]
                cmd += ["-w", "/src", "semgrep/semgrep", "semgrep", "scan",
                        f"--config={config}", ".", "--exclude", "semgrep-rules",
                        "--sarif", "--output", f"/out/{out_name}", "--metrics=off"]
                return subprocess.run(cmd, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=1800)

            if rules_dir is not None:
                r = semgrep("/rules/sast-detect.yaml", f_sast.name)
                # Bo sanitizer chay cung luc - khong co no thi khong co FILTERED
                if (rules_dir / "sanitizer-check.yaml").is_file():
                    semgrep("/rules/sanitizer-check.yaml", f_san.name)
            else:
                r = semgrep("p/csharp", f_sast.name)

            if f_sast.exists():
                n = sum(len(run.get("results", [])) for run in
                        json.loads(f_sast.read_text(encoding="utf-8")).get("runs", []))
                them = ""
                if rules_dir is not None and f_san.exists():
                    ns = sum(len(run.get("results", [])) for run in
                             json.loads(f_san.read_text(encoding="utf-8")).get("runs", []))
                    them = f" · {ns} bằng chứng khử độc"
                elif rules_dir is None:
                    them = " · không có bộ sanitizer nên sẽ không có nhãn FILTERED"
                done("sast", t0, "ok", f"{n} cảnh báo từ {nguon}{them}")
            else:
                done("sast", t0, "fail", short_err(r.stderr, r.stdout))

        # ---------------- Tang 3: ban do endpoint ----------------
        t0 = begin("routes")
        subprocess.run(
            [sys.executable, str(TOOLS / "gen_routes_map.py"), "--root", str(repo_path),
             "--base-url", base_url or "http://localhost:5000", "--out", str(f_routes)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, cwd=ROOT)
        if f_routes.exists():
            s = json.loads(f_routes.read_text(encoding="utf-8")).get("summary", {})
            tot = sum(s.values()) or 1
            done("routes", t0, "ok",
                 f"{s.get('testable', 0)}/{tot} endpoint kiểm thử động được "
                 f"({s.get('testable', 0) / tot * 100:.0f}%)")
        else:
            done("routes", t0, "fail", "không tìm thấy Controller hay Razor Page nào")

        # ---------------- Tang 4: ha tang ----------------
        t0 = begin("trivy")
        if not use_trivy:
            done("trivy", t0, "skip", "đã tắt trong tuỳ chọn")
        elif not docker_ready()[0]:
            done("trivy", t0, "skip",
                 f"{docker_ready()[1]} — chưa kiểm tra được hạ tầng")
        else:
            r = subprocess.run(
                [sys.executable, str(TOOLS / "trivy.py"), "--config", str(repo_path),
                 "--sbom", str(repo_path), "--out-prefix", f"trivy_{slug}"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=2400, cwd=ROOT)
            if f_trivy.exists():
                t = json.loads(f_trivy.read_text(encoding="utf-8"))
                cfg = (t.get("config") or {}).get("total", 0)
                sb = (t.get("sbom") or {}).get("components", 0)
                done("trivy", t0, "ok", f"{cfg} lỗi cấu hình · SBOM {sb} thành phần")
            else:
                done("trivy", t0, "fail", short_err(r.stderr, r.stdout))

        # ---------------- Tang 5: doi sanh ----------------
        t0 = begin("dast")
        if not base_url:
            done("dast", t0, "skip",
                 "chưa cho biết ứng dụng chạy ở đâu — không có gì để bắn payload vào")
        elif not f_sast.exists():
            done("dast", t0, "skip", "không có kết quả tĩnh để đối sánh")
        elif not http_ok(f"{ZAP_URL}/JSON/core/view/version/"):
            done("dast", t0, "skip",
                 "không kết nối được ZAP ở cổng 8090 — chưa kiểm chứng được cảnh báo nào")
        elif not app_alive(base_url)[0]:
            done("dast", t0, "skip",
                 f"ung dung dich khong phan hoi — {app_alive(base_url)[1]}")
        else:
            r = subprocess.run(
                [sys.executable, str(TOOLS / "correlate.py"),
                 "--findings", str(f_sast),
                 # Chi dung bang chung khu doc cua chinh lan quet nay. Khong
                 # muon lay tep sanitizers.sarif cua lan chay khac: nhan
                 # FILTERED phai dua tren bang chung cung mot ban ma nguon.
                 # Thieu tep thi correlate.py canh bao va coi nhu khong co
                 # bang chung loai tru - khong tu bia ra nhan FILTERED.
                 "--sanitizers", str(f_san),
                 "--routes", str(f_routes), "--base-url", base_url,
                 "--out", str(f_dast),
                 "--sarif-out", str(REPORTS / f"correlated_{slug}.sarif")],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600, cwd=ROOT)
            if f_dast.exists():
                d = json.loads(f_dast.read_text(encoding="utf-8"))["summary"]
                nc = d.get("CONFIRMED", 0)
                # Phan biet hai chuyen khac han nhau:
                #   "fail"  = buoc nay chay khong duoc (loi ky thuat)
                #   "gate"  = buoc nay chay dung, nhung cong chat luong chan
                #             vi tim thay lo hong da xac nhan khai thac duoc
                # Gop hai cai vao mot nhan "hong" la sai: mot ket qua 4
                # CONFIRMED la cong cu lam DUNG viec cua no, khong phai hong.
                tom_tat = (f"CONFIRMED {nc} · FILTERED {d.get('FILTERED', 0)} · "
                           f"UNCONFIRMED {d.get('UNCONFIRMED', 0)}")
                if nc:
                    done("dast", t0, "gate",
                         f"{tom_tat} — cổng chất lượng chặn: {nc} lỗ hổng đã "
                         f"xác nhận khai thác được")
                else:
                    done("dast", t0, "ok", f"{tom_tat} — cổng chất lượng cho qua")
            else:
                done("dast", t0, "fail", short_err(r.stderr, r.stdout))

        # ---------------- Bao cao ----------------
        t0 = begin("report")
        args = [sys.executable, str(TOOLS / "report.py"), "--title", title,
                "--out", str(f_html)]
        for flag, p in (("--sca", f_sca), ("--sast", f_sast), ("--routes", f_routes),
                        ("--dast", f_dast), ("--trivy", f_trivy)):
            if p.exists():
                args += [flag, str(p)]
        subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, cwd=ROOT)
        if f_html.exists():
            job["report"] = f_html.name
            job["findings"] = (json.loads(f_dast.read_text(encoding="utf-8"))
                               if f_dast.exists() else None)
            done("report", t0, "ok", "trang báo cáo đã sẵn sàng")
        else:
            done("report", t0, "fail", "không dựng được trang báo cáo")

    except Exception as exc:
        job["error"] = str(exc)
        job["log"].append({"t": time.strftime("%H:%M:%S"), "m": f"LỖI: {exc}", "k": "err"})
        for s in job["stages"]:
            if s["state"] in ("pending", "running"):
                s["state"] = "skip"
                s["detail"] = "không chạy vì lần quét đã dừng"
    finally:
        job["done"] = True
        job["step"] = ""


# ==========================================================================
PAGE = r"""<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bảng điều khiển DevSecOps</title>
<style>
  :root { color-scheme: light; --surface:#fcfcfb; --plane:#f4f4f1; --ink:#0b0b0b;
    --ink2:#52514e; --muted:#898781; --grid:#e1e0d9; --ring:rgba(11,11,11,.10);
    --accent:#2a6fd6; --ok:#0a8a0a; --warn:#b06a14; --err:#c8402f;
    --okbg:#e9f6e9; --warnbg:#fdf3e6; --errbg:#fdecec; }
  @media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
    color-scheme: dark; --surface:#1a1a19; --plane:#0d0d0d; --ink:#fff;
    --ink2:#c3c2b7; --grid:#2c2c2a; --ring:rgba(255,255,255,.12); --accent:#4a8ee8;
    --ok:#4bbd4b; --warn:#e0a24a; --err:#e8695a;
    --okbg:#142a14; --warnbg:#2c2314; --errbg:#2e1816; } }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--plane); color:var(--ink);
    font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif; }
  .wrap { max-width:1120px; margin:0 auto; padding:24px 16px 72px; }
  h1 { font-size:22px; margin:0 0 4px; letter-spacing:-.01em; }
  h2 { font-size:17px; margin:26px 0 10px; }
  h3 { font-size:14px; margin:0 0 6px; }
  .sub { color:var(--ink2); font-size:14px; margin-bottom:20px; }
  .card { background:var(--surface); border:1px solid var(--ring);
    border-radius:12px; padding:20px 22px; margin-bottom:14px; }
  .tabs { display:flex; gap:4px; border-bottom:1px solid var(--grid); margin-bottom:20px; }
  .tab { padding:10px 18px; font:600 14px system-ui,sans-serif; cursor:pointer;
    border:0; background:none; color:var(--ink2); border-bottom:2px solid transparent; }
  .tab[aria-selected="true"] { color:var(--ink); border-bottom-color:var(--accent); }
  label { display:block; font-size:13px; color:var(--ink2); margin-bottom:6px; }
  input[type=text] { width:100%; padding:10px 12px; font:14px ui-monospace,Consolas,monospace;
    background:var(--plane); color:var(--ink); border:1px solid var(--grid); border-radius:8px; }
  .row { display:grid; grid-template-columns:2fr 1fr; gap:14px; margin-bottom:14px; }
  .opts { display:flex; align-items:center; gap:8px; margin:8px 0; font-size:13.5px; color:var(--ink2); }
  button.go { background:var(--accent); color:#fff; border:0; border-radius:8px;
    padding:11px 24px; font:600 14.5px system-ui,sans-serif; cursor:pointer; }
  button.go:disabled { opacity:.45; cursor:default; }
  button.ghost { background:none; border:1px solid var(--grid); color:var(--ink2);
    border-radius:8px; padding:8px 14px; font:600 13px system-ui,sans-serif; cursor:pointer; }
  table { width:100%; border-collapse:collapse; font-size:13.5px; }
  th { text-align:left; font-weight:600; color:var(--ink2); font-size:12px;
    text-transform:uppercase; letter-spacing:.04em;
    border-bottom:1px solid var(--grid); padding:8px 10px 8px 0; }
  td { padding:9px 10px 9px 0; border-bottom:1px solid var(--grid); vertical-align:top; }
  code { font:12.5px ui-monospace,Consolas,monospace; }
  .pill { display:inline-block; padding:2px 9px; border-radius:20px;
    font:600 11.5px system-ui,sans-serif; white-space:nowrap; }
  .p-ok { background:var(--okbg); color:var(--ok); }
  .p-warn { background:var(--warnbg); color:var(--warn); }
  .p-err { background:var(--errbg); color:var(--err); }
  .p-idle { background:var(--plane); color:var(--muted); }
  .stage { display:grid; grid-template-columns:22px 1fr auto; gap:14px;
    padding:14px 0; border-bottom:1px solid var(--grid); align-items:start; }
  .stage:last-child { border-bottom:0; }
  .dot { width:14px; height:14px; border-radius:50%; margin-top:4px;
    border:2px solid var(--grid); }
  .dot.running { border-color:var(--accent); border-top-color:transparent;
    animation:spin .8s linear infinite; }
  .dot.ok { background:var(--ok); border-color:var(--ok); }
  .dot.fail, .dot.gate { background:var(--err); border-color:var(--err); }
  .dot.skip { background:var(--muted); border-color:var(--muted); opacity:.5; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .st-name { font-weight:620; font-size:14.5px; }
  .st-flow { color:var(--muted); font-size:12.5px; margin-top:2px; }
  .st-detail { font-size:13px; margin-top:5px; color:var(--ink2); }
  .st-detail.fail, .st-detail.gate { color:var(--err); }
  .st-detail.skip { color:var(--warn); }
  .secs { color:var(--muted); font-size:12.5px; font-variant-numeric:tabular-nums; }
  .log { background:var(--plane); border:1px solid var(--grid); border-radius:8px;
    padding:12px 14px; font:12.5px/1.75 ui-monospace,Consolas,monospace;
    max-height:220px; overflow:auto; white-space:pre-wrap; margin-top:14px; }
  .log .t { color:var(--muted); } .log .ok { color:var(--ok); }
  .log .warn { color:var(--warn); } .log .err { color:var(--err); }
  iframe { width:100%; height:70vh; border:1px solid var(--ring);
    border-radius:12px; background:var(--surface); }
  .hint { color:var(--muted); font-size:12.5px; }
  .hidden { display:none; }
  .lbl { display:grid; grid-template-columns:150px 1fr; gap:16px; padding:14px 0;
    border-bottom:1px solid var(--grid); }
  .lbl:last-child { border-bottom:0; }
  .lbl-name { font:600 14px ui-monospace,Consolas,monospace; }
  .quote { border-left:3px solid var(--accent); padding-left:14px; color:var(--ink2);
    font-size:14px; margin:14px 0; }
  .grid3 { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:12px; }
  .mini { background:var(--plane); border:1px solid var(--grid); border-radius:10px; padding:14px 16px; }
  .mini b { display:block; font-size:24px; font-weight:640; margin-bottom:2px; }
  .mini span { color:var(--ink2); font-size:12.5px; }
</style></head><body><div class="wrap">

<h1>Bảng điều khiển DevSecOps</h1>
<div class="sub">Xây dựng quy trình DevSecOps tích hợp kiểm thử SAST và DAST — Huỳnh Thanh Tùng, 246204907</div>

<div class="tabs" role="tablist">
  <button class="tab" role="tab" aria-selected="true" data-p="p1">Tổng quan</button>
  <button class="tab" role="tab" aria-selected="false" data-p="p2">Chạy quét</button>
  <button class="tab" role="tab" aria-selected="false" data-p="p3">Kết quả</button>
</div>

<!-- ================= TAB 1 ================= -->
<div id="p1">
  <div class="card">
    <h3>Vấn đề</h3>
    <p style="margin:6px 0 0;color:var(--ink2)">SAST chỉ đúng <b>dòng nào</b> sinh lỗi nhưng hay báo nhầm.
    DAST chứng minh được <b>khai thác được thật</b> nhưng không biết sửa ở đâu. Đồ án đảo chiều:
    <b>kết quả SAST quyết định DAST quét cái gì</b>, rồi gán nhãn theo loại bằng chứng.</p>
  </div>

  <div class="card">
    <h3>Quy chế ba nhãn — gán theo <i>loại bằng chứng</i>, không theo kết quả quét</h3>
    <div class="lbl"><div class="lbl-name" style="color:var(--err)">CONFIRMED</div>
      <div>Bằng chứng <b>động</b>, khẳng định: ZAP khai thác thành công tại đúng cặp (URL, tham số)
      với confidence từ Medium trở lên.<br><span class="hint">→ Chặn build, nhánh không merge được</span></div></div>
    <div class="lbl"><div class="lbl-name" style="color:var(--ok)">FILTERED</div>
      <div>Bằng chứng <b>tĩnh</b>, loại trừ: rule tìm thấy hàm khử độc nằm trên đúng luồng dữ liệu đó.
      <br><span class="hint">→ Ghi phụ lục, đánh dấu suppressed — không xoá khỏi báo cáo</span></div></div>
    <div class="lbl"><div class="lbl-name" style="color:var(--muted)">UNCONFIRMED</div>
      <div>Không có bằng chứng nào thuộc hai loại trên. <b>Đây là nhãn mặc định.</b>
      <br><span class="hint">→ Nợ kiểm thử, chờ người xem lại</span></div></div>
    <div class="quote"><b>Im lặng không phải là bằng chứng.</b> Scanner không tìm thấy gì chỉ chứng minh
    scanner không tìm thấy gì. Nghi ngờ thì rơi về UNCONFIRMED, không rơi về FILTERED — hệ an ninh phải fail-closed.</div>
  </div>

  <div class="card">
    <h3>Bốn cổng cưỡng chế</h3>
    <table><thead><tr><th>Cổng</th><th>Kích hoạt bởi</th><th>Chạy gì</th><th>Chặn được gì</th></tr></thead><tbody>
      <tr><td>1. IDE</td><td>lúc gõ code</td><td>—</td><td><span class="pill p-idle">ngoài phạm vi</span></td></tr>
      <tr><td>2. pre-commit</td><td><code>git commit</code></td><td>SAST, chỉ tệp đang commit</td>
          <td><span class="pill p-warn">chặn commit · bỏ qua được</span></td></tr>
      <tr><td>3. CI / Pull Request</td><td><code>git push</code>, mở PR</td><td><b>cả 5 tầng</b></td>
          <td><span class="pill p-err">chặn merge · không bỏ qua được</span></td></tr>
      <tr><td>4. Quét định kỳ</td><td>lịch hằng tuần</td><td>SCA + hạ tầng</td>
          <td><span class="pill p-idle">không chặn, mở issue</span></td></tr>
    </tbody></table>
    <p class="hint" style="margin-top:12px">Ba cổng đầu đều kích hoạt bởi một <i>thay đổi mã nguồn</i>, nên cả ba
    mù với cùng một rủi ro: mã nguồn đứng yên nhưng CVE mới vẫn được công bố. Cổng 4 tồn tại vì lý do đó.</p>
  </div>

  <div class="card">
    <h3>Kết quả đã đo được</h3>
    <div class="grid3">
      <div class="mini"><b>100%</b><span>tỉ lệ phân giải trên bộ ground truth — 4 CONFIRMED, 2 FILTERED, 0 UNCONFIRMED</span></div>
      <div class="mini"><b>0 / 4</b><span>quét mù tìm được, trong 474 giây — spider không thấy endpoint có tham số</span></div>
      <div class="mini"><b>432 → 235</b><span>số CVE trong container image sau khi gia cố · Critical 13 → 4</span></div>
      <div class="mini"><b>422 / 432</b><span>lỗ hổng image đến từ gói hệ điều hành, ngoài tầm nhìn của SAST, DAST và SCA</span></div>
      <div class="mini"><b>4 / 43</b><span>endpoint eShopOnWeb kiểm thử động được ngay — 65% nằm sau đăng nhập</span></div>
      <div class="mini"><b>6 / 13</b><span>kiểm soát DevSecOps mà đồ án phủ — tập trung ở Code–Build–Test</span></div>
    </div>
  </div>
</div>

<!-- ================= TAB 2 ================= -->
<div id="p2" class="hidden">
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="margin:0">Kiểm tra môi trường</h3>
      <button class="ghost" id="recheck">Kiểm tra lại</button>
    </div>
    <p class="hint" style="margin:0 0 12px">Xem trước cái gì sẵn sàng, để không phát hiện Docker chưa bật vào giữa buổi demo.</p>
    <table id="pf"><tbody><tr><td class="hint">đang kiểm tra...</td></tr></tbody></table>
  </div>

  <div class="card">
    <div class="row">
      <div><label for="repo">Đường dẫn thư mục mã nguồn</label>
        <input id="repo" type="text" placeholder="đường dẫn tới repo cần quét"></div>
      <div><label for="title">Tên hiển thị</label>
        <input id="title" type="text" placeholder="tên hiện trên báo cáo"></div>
    </div>
    <div class="row">
      <div><label for="base">URL ứng dụng <span class="hint">— địa chỉ mà ZAP nhìn thấy, không phải địa chỉ trên trình duyệt bạn</span></label>
        <input id="base" type="text" placeholder="http://host.docker.internal:5000"></div>
      <div><label>&nbsp;</label><div class="hint">ZAP chạy trong container nên
        <code>localhost</code> với nó là chính nó. Để trống thì bỏ qua tầng đối sánh.
        Cần ZAP ở cổng 8090.</div></div>
    </div>
    <div class="opts"><input id="sast" type="checkbox" checked>
      <label for="sast" style="margin:0">Quét mã nguồn bằng Semgrep (cần Docker)</label></div>
    <div class="opts"><input id="trivy" type="checkbox">
      <label for="trivy" style="margin:0">Quét hạ tầng: cấu hình triển khai + SBOM (cần Docker)</label></div>
    <button class="go" id="go">Bắt đầu quét</button>
    <span class="hint" style="margin-left:12px">Không sửa gì trong repo. Kết quả ghi vào <code>reports/</code>.</span>
  </div>

  <div class="card hidden" id="progress">
    <h3 id="status" style="margin-bottom:14px"></h3>
    <div id="stages"></div>
    <div class="log" id="log"></div>
  </div>
</div>

<!-- ================= TAB 3 ================= -->
<div id="p3" class="hidden">
  <div class="card" id="nores">
    <p class="hint" style="margin:0">Chưa có kết quả. Sang thẻ <b>Chạy quét</b> và bấm Bắt đầu.</p>
  </div>
  <div class="card hidden" id="findwrap">
    <h3>Từng cảnh báo và bằng chứng của nó</h3>
    <table><thead><tr><th>Nhãn</th><th>CWE</th><th>Vị trí trong mã</th><th>Điểm kiểm thử</th><th>Bằng chứng</th></tr></thead>
    <tbody id="findings"></tbody></table>
  </div>
  <iframe class="hidden" id="frame" title="Báo cáo"></iframe>
</div>

</div>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
let jobId = null, timer = null;

document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.setAttribute('aria-selected', x === t));
  ['p1','p2','p3'].forEach(p => $(p).classList.toggle('hidden', p !== t.dataset.p));
});

async function checkEnv() {
  $('pf').innerHTML = '<tbody><tr><td class="hint">đang kiểm tra...</td></tr></tbody>';
  const base = $('base').value.trim();
  const rows = await (await fetch('/api/preflight?base=' + encodeURIComponent(base))).json();
  $('pf').innerHTML = '<tbody>' + rows.map(r => `<tr>
    <td style="width:150px"><b>${esc(r.name)}</b></td>
    <td style="width:110px"><span class="pill ${r.ok ? 'p-ok' : 'p-warn'}">${r.ok ? 'sẵn sàng' : 'chưa có'}</span></td>
    <td>${esc(r.detail)}</td>
    <td class="hint" style="width:210px">${esc(r.need)} — ${esc(r.layers)}</td></tr>`).join('') + '</tbody>';
}
$('recheck').onclick = checkEnv;
checkEnv();

$('go').onclick = async () => {
  const repo = $('repo').value.trim();
  if (!repo) { $('repo').focus(); return; }
  const title = $('title').value.trim() || repo.split(/[\\/]/).filter(Boolean).pop();
  $('go').disabled = true;
  $('progress').classList.remove('hidden');
  $('log').textContent = ''; $('stages').innerHTML = '';
  $('nores').classList.remove('hidden');
  $('findwrap').classList.add('hidden'); $('frame').classList.add('hidden');
  const r = await fetch('/api/scan', { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ repo, title, sast: $('sast').checked,
      base_url: $('base').value.trim(), trivy: $('trivy').checked }) });
  jobId = (await r.json()).id;
  timer = setInterval(poll, 700);
};

const WORD = { pending:'chờ', running:'đang chạy', ok:'xong', skip:'bỏ qua',
               fail:'hỏng', gate:'cổng chặn' };
const PILL = { pending:'p-idle', running:'p-idle', ok:'p-ok', skip:'p-warn',
               fail:'p-err', gate:'p-err' };

async function poll() {
  const j = await (await fetch('/api/status?id=' + jobId)).json();

  $('stages').innerHTML = (j.stages || []).map(s => `
    <div class="stage">
      <div class="dot ${s.state}"></div>
      <div>
        <div class="st-name">${esc(s.name)}</div>
        <div class="st-flow">${esc(s.tool)} · ${esc(s.input)} → ${esc(s.output)}</div>
        ${s.detail ? `<div class="st-detail ${s.state}">${esc(s.detail)}</div>` : ''}
      </div>
      <div style="text-align:right">
        <span class="pill ${PILL[s.state]}">${WORD[s.state]}</span>
        ${s.seconds ? `<div class="secs">${s.seconds}s</div>` : ''}
      </div>
    </div>`).join('');

  $('log').innerHTML = (j.log || []).map(l =>
    `<span class="t">${l.t}</span>  <span class="${l.k}">${esc(l.m)}</span>`).join('\n');
  $('log').scrollTop = $('log').scrollHeight;
  $('status').textContent = j.done ? (j.error ? 'Dừng vì lỗi' : 'Hoàn tất') : (j.step || 'Đang chạy...');

  if (!j.done) return;
  clearInterval(timer);
  $('go').disabled = false;

  const f = j.findings;
  if (f && f.results) {
    const COLOR = { CONFIRMED:'p-err', FILTERED:'p-ok', UNCONFIRMED:'p-idle' };
    const ORD = { CONFIRMED:0, UNCONFIRMED:1, FILTERED:2 };
    $('findings').innerHTML = f.results
      .sort((a,b) => (ORD[a.label] ?? 9) - (ORD[b.label] ?? 9))
      .map(x => `<tr>
        <td><span class="pill ${COLOR[x.label] || 'p-idle'}">${esc(x.label)}</span></td>
        <td style="white-space:nowrap">${esc(x.cwe)}</td>
        <td><code>${esc(x.file)}:${x.line}</code></td>
        <td>${x.url ? `<code>${esc(x.url)}?${esc(x.param)}=</code>` : '<span class="hint">không ánh xạ được</span>'}</td>
        <td class="hint">${esc(x.evidence)}</td></tr>`).join('');
    $('findwrap').classList.remove('hidden');
    $('nores').classList.add('hidden');
  }
  if (j.report) {
    $('frame').src = '/reports/' + j.report + '?t=' + Date.now();
    $('frame').classList.remove('hidden');
    $('nores').classList.add('hidden');
    document.querySelector('.tab[data-p="p3"]').click();
  }
}
</script></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj) -> None:
        self._send(200, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self) -> None:
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif u.path == "/api/preflight":
            self._json(preflight(q.get("base", [""])[0]))
        elif u.path == "/api/status":
            self._json(JOBS.get(q.get("id", [""])[0],
                                {"log": [], "stages": [], "done": True,
                                 "error": "khong tim thay job"}))
        elif u.path.startswith("/reports/"):
            f = REPORTS / Path(u.path).name
            if f.exists() and f.suffix == ".html":
                self._send(200, f.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(404, b"khong tim thay", "text/plain")
        else:
            self._send(404, b"khong tim thay", "text/plain")

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/scan":
            self._send(404, b"", "text/plain")
            return
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        base_url = req.get("base_url", "").strip()
        use_sast = bool(req.get("sast", True))
        use_trivy = bool(req.get("trivy", False))

        jid = uuid.uuid4().hex[:12]
        JOBS[jid] = {"log": [], "done": False, "report": None, "error": None,
                     "step": "", "findings": None,
                     "stages": new_stages(base_url, use_sast, use_trivy)}
        threading.Thread(
            target=run_scan,
            args=(jid, req.get("repo", ""), req.get("title", "Repo"),
                  use_sast, base_url, use_trivy),
            daemon=True).start()
        self._json({"id": jid})

    def log_message(self, *a) -> None:
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    url = f"http://localhost:{args.port}"
    print(f"Bang dieu khien dang chay tai {url}")
    print("Nhan Ctrl+C de dung.\n")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", args.port), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nDa dung.")


if __name__ == "__main__":
    main()
