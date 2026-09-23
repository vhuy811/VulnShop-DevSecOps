#!/usr/bin/env python3
"""
Giao dien web cuc bo cho cong cu quet.

Chay mot may chu HTTP nho tren localhost. Nguoi dung dan duong dan repo,
bam Quet, xem tung tang chay truc tiep, roi bao cao hien ngay trong trang.

Chi dung thu vien chuan cua Python - khong cai them gi.

Cach dung:
    python tools/webui.py
    (tu mo trinh duyet tai http://localhost:8000)
"""
from __future__ import annotations

import argparse
import http.server
import json
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

JOBS: dict[str, dict] = {}


# --------------------------------------------------------------------------
# Chay mot lan quet
# --------------------------------------------------------------------------
def zap_alive(zap_url: str = "http://localhost:8090") -> bool:
    """ZAP co dang chay khong. Hoi truoc con hon treo 3 phut roi bao loi."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{zap_url}/JSON/core/view/version/", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def run_scan(job_id: str, repo: str, title: str, use_sast: bool,
             base_url: str = "", use_trivy: bool = False) -> None:
    job = JOBS[job_id]

    def log(msg: str, kind: str = "info") -> None:
        job["log"].append({"t": time.strftime("%H:%M:%S"), "m": msg, "k": kind})

    try:
        repo_path = Path(repo).expanduser().resolve()
        if not repo_path.is_dir():
            raise FileNotFoundError(f"Khong tim thay thu muc: {repo_path}")

        slug = "".join(c if c.isalnum() else "_" for c in title)[:40] or "target"
        sca_json = REPORTS / f"sca_{slug}.json"
        sast_sarif = REPORTS / f"sast_{slug}.sarif"
        routes_json = REPORTS / f"routes_{slug}.json"
        dast_json = REPORTS / f"dast_{slug}.json"
        trivy_json = REPORTS / f"trivy_{slug}.json"
        out_html = REPORTS / f"bao_cao_{slug}.html"

        n_layers = 3 + (1 if base_url else 0) + (1 if use_trivy else 0)
        log(f"Muc tieu: {repo_path}")

        # ---- Tang 1: SCA ----
        job["step"] = "Tầng 1 — thư viện"
        log(f"Tang 1/{n_layers}: quet thu vien, doi chieu CSDL lo hong da cong bo...")
        r = subprocess.run(
            [sys.executable, str(TOOLS / "sca.py"), "--repo", str(repo_path),
             "--out", str(sca_json)],
            capture_output=True, text=True, timeout=1800, cwd=ROOT,
        )
        if sca_json.exists():
            s = json.loads(sca_json.read_text(encoding="utf-8"))["summary"]
            log(f"  {s['packages']} goi dinh lo hong, {s['advisories']} advisory "
                f"(Critical {s['by_severity']['Critical']}, High {s['by_severity']['High']})",
                "ok")
        else:
            log("  Khong chay duoc tang SCA: " + (r.stderr or r.stdout)[-200:], "warn")

        # ---- Tang 2: SAST ----
        job["step"] = "Tầng 2 — mã nguồn"
        if use_sast and shutil.which("docker"):
            log(f"Tang 2/{n_layers}: phan tich tinh bang bo rule cong dong "
                f"(tai rule lan dau, hoi lau)...")
            r = subprocess.run(
                ["docker", "run", "--rm",
                 "-v", f"{repo_path}:/src:ro",
                 "-v", f"{REPORTS}:/out",
                 "-w", "/src", "semgrep/semgrep",
                 "semgrep", "scan", "--config=p/csharp", ".",
                 "--sarif", "--output", f"/out/{sast_sarif.name}", "--metrics=off"],
                capture_output=True, text=True, timeout=1800,
            )
            if sast_sarif.exists():
                n = sum(len(run.get("results", []))
                        for run in json.loads(sast_sarif.read_text(encoding="utf-8")).get("runs", []))
                log(f"  {n} canh bao ma nguon", "ok")
            else:
                log("  Semgrep khong tao duoc ket qua: " + (r.stderr or "")[-200:], "warn")
        else:
            log(f"Tang 2/{n_layers}: bo qua (khong co Docker hoac da tat)", "warn")

        # ---- Tang 3: pham vi ----
        job["step"] = "Tầng 3 — phạm vi"
        log(f"Tang 3/{n_layers}: lap ban do endpoint, do pham vi kiem thu dong duoc...")
        subprocess.run(
            [sys.executable, str(TOOLS / "gen_routes_map.py"), "--root", str(repo_path),
             "--out", str(routes_json)],
            capture_output=True, text=True, timeout=600, cwd=ROOT,
        )
        if routes_json.exists():
            s = json.loads(routes_json.read_text(encoding="utf-8")).get("summary", {})
            tot = sum(s.values())
            log(f"  {s.get('testable', 0)}/{tot} endpoint kiem thu dong duoc", "ok")
        else:
            log("  Khong tim thay Controller nao trong repo nay", "warn")

        # ---- Tang 4: DAST + doi sanh ba nhan ----
        # Chi chay khi nguoi dung cho biet app dang chay o dau. Khong co URL thi
        # khong co gi de ban payload vao - va bo qua co y thuc van tot hon la
        # chay roi bao "khong tim thay lo hong".
        if base_url:
            job["step"] = "Tầng 4 — đối sánh"
            if not sast_sarif.exists():
                log("Tang 4: bo qua - khong co ket qua tinh de doi sanh", "warn")
            elif not zap_alive():
                log("Tang 4: bo qua - khong ket noi duoc ZAP tai localhost:8090.", "warn")
                log("  Khoi dong: zap.bat -daemon -port 8090 "
                    "-config api.disablekey=true", "warn")
            else:
                log(f"Tang 4/{n_layers}: kiem chung tung canh bao tren app dang chay "
                    f"tai {base_url} ...")
                r = subprocess.run(
                    [sys.executable, str(TOOLS / "correlate.py"),
                     "--findings", str(sast_sarif),
                     "--sanitizers", str(REPORTS / "sanitizers.sarif"),
                     "--routes", str(routes_json),
                     "--base-url", base_url,
                     "--out", str(dast_json),
                     "--sarif-out", str(REPORTS / f"correlated_{slug}.sarif")],
                    capture_output=True, text=True, timeout=3600, cwd=ROOT,
                )
                if dast_json.exists():
                    d = json.loads(dast_json.read_text(encoding="utf-8"))["summary"]
                    log(f"  CONFIRMED {d.get('CONFIRMED', 0)} · "
                        f"FILTERED {d.get('FILTERED', 0)} · "
                        f"UNCONFIRMED {d.get('UNCONFIRMED', 0)}",
                        "err" if d.get("CONFIRMED") else "ok")
                else:
                    log("  Doi sanh that bai: " + (r.stderr or r.stdout)[-240:], "warn")

        # ---- Tang 5: ha tang ----
        # Chi quet cau hinh va sinh SBOM. Buoc build/so sanh image mat 5-10 phut
        # nen de rieng cho dong lenh, khong nhet vao giao dien.
        if use_trivy:
            job["step"] = "Tầng 5 — hạ tầng"
            if not shutil.which("docker"):
                log("Tang 5: bo qua - khong co Docker", "warn")
            else:
                log(f"Tang 5/{n_layers}: quet cau hinh trien khai va sinh SBOM...")
                r = subprocess.run(
                    [sys.executable, str(TOOLS / "trivy.py"),
                     "--config", str(repo_path), "--sbom", str(repo_path),
                     "--out-prefix", f"trivy_{slug}"],
                    capture_output=True, text=True, timeout=2400, cwd=ROOT,
                )
                if trivy_json.exists():
                    t = json.loads(trivy_json.read_text(encoding="utf-8"))
                    cfg = (t.get("config") or {}).get("total", 0)
                    sb = (t.get("sbom") or {}).get("components", 0)
                    log(f"  {cfg} loi cau hinh · SBOM {sb} thanh phan", "ok")
                else:
                    log("  Trivy that bai: " + (r.stderr or r.stdout)[-240:], "warn")

        # ---- Bao cao ----
        job["step"] = "Dựng báo cáo"
        log("Dung trang bao cao...")
        args = [sys.executable, str(TOOLS / "report.py"), "--title", title,
                "--out", str(out_html)]
        for flag, p in (("--sca", sca_json), ("--sast", sast_sarif),
                        ("--routes", routes_json), ("--dast", dast_json),
                        ("--trivy", trivy_json)):
            if p.exists():
                args += [flag, str(p)]
        subprocess.run(args, capture_output=True, text=True, timeout=300, cwd=ROOT)

        if not out_html.exists():
            raise RuntimeError("Khong dung duoc trang bao cao")

        job["report"] = out_html.name
        log("Xong.", "ok")

    except Exception as exc:
        job["error"] = str(exc)
        job["log"].append({"t": time.strftime("%H:%M:%S"), "m": f"LOI: {exc}", "k": "err"})
    finally:
        job["done"] = True
        job["step"] = ""


# --------------------------------------------------------------------------
PAGE = """<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Công cụ quét bảo mật mã nguồn</title>
<style>
  :root { color-scheme: light; --surface:#fcfcfb; --plane:#f9f9f7; --ink:#0b0b0b;
    --ink2:#52514e; --muted:#898781; --grid:#e1e0d9; --ring:rgba(11,11,11,.10);
    --accent:#2a78d6; --ok:#0ca30c; --warn:#fab219; --err:#d03b3b; }
  @media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
    color-scheme: dark; --surface:#1a1a19; --plane:#0d0d0d; --ink:#fff;
    --ink2:#c3c2b7; --grid:#2c2c2a; --ring:rgba(255,255,255,.10); --accent:#3987e5; } }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--plane); color:var(--ink);
    font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif; }
  .wrap { max-width:1080px; margin:0 auto; padding:28px 16px 60px; }
  h1 { font-size:22px; margin:0 0 4px; letter-spacing:-.01em; }
  .sub { color:var(--ink2); font-size:14px; margin-bottom:24px; }
  .card { background:var(--surface); border:1px solid var(--ring);
    border-radius:12px; padding:20px 22px; margin-bottom:16px; }
  label { display:block; font-size:13px; color:var(--ink2); margin-bottom:6px; }
  input[type=text] { width:100%; padding:10px 12px; font:14px ui-monospace,Consolas,monospace;
    background:var(--plane); color:var(--ink); border:1px solid var(--grid);
    border-radius:8px; }
  .row { display:grid; grid-template-columns:2fr 1fr; gap:14px; }
  .opts { display:flex; align-items:center; gap:8px; margin:14px 0 16px;
    font-size:13.5px; color:var(--ink2); }
  button { background:var(--accent); color:#fff; border:0; border-radius:8px;
    padding:11px 24px; font:600 14.5px system-ui,sans-serif; cursor:pointer; }
  button:disabled { opacity:.5; cursor:default; }
  .log { background:var(--plane); border:1px solid var(--grid); border-radius:8px;
    padding:12px 14px; font:12.5px/1.75 ui-monospace,Consolas,monospace;
    max-height:280px; overflow:auto; white-space:pre-wrap; }
  .log .t { color:var(--muted); }
  .log .ok { color:var(--ok); } .log .warn { color:var(--warn); }
  .log .err { color:var(--err); }
  .status { font-size:13.5px; color:var(--ink2); margin-bottom:10px; min-height:20px; }
  .spin { display:inline-block; width:10px; height:10px; border-radius:50%;
    border:2px solid var(--accent); border-top-color:transparent;
    animation:s .8s linear infinite; margin-right:7px; vertical-align:-1px; }
  @keyframes s { to { transform:rotate(360deg); } }
  iframe { width:100%; height:78vh; border:1px solid var(--ring);
    border-radius:12px; background:var(--surface); }
  .hint { color:var(--muted); font-size:12.5px; margin-top:8px; }
  .opt { color:var(--muted); font-weight:400; }
  .hidden { display:none; }
</style></head><body><div class="wrap">
  <h1>Công cụ quét bảo mật mã nguồn</h1>
  <div class="sub">Thư viện (CVE) · mã nguồn (CWE) · phạm vi endpoint · đối sánh ba nhãn · hạ tầng</div>

  <div class="card">
    <div class="row">
      <div>
        <label for="repo">Đường dẫn thư mục mã nguồn</label>
        <input id="repo" type="text" placeholder="C:\\Users\\Admin\\Downloads\\ATWcsdl\\eShopOnWeb">
      </div>
      <div>
        <label for="title">Tên hiển thị</label>
        <input id="title" type="text" placeholder="eShopOnWeb">
      </div>
    </div>
    <div class="row" style="margin-top:14px">
      <div>
        <label for="base">URL ứng dụng đang chạy <span class="opt">— để trống thì bỏ qua tầng kiểm thử động</span></label>
        <input id="base" type="text" placeholder="http://localhost:5000">
      </div>
      <div>
        <label>&nbsp;</label>
        <div class="hint" style="margin:0">Cần ZAP chạy ở cổng 8090</div>
      </div>
    </div>
    <div class="opts">
      <input id="sast" type="checkbox" checked>
      <label for="sast" style="margin:0">Quét mã nguồn bằng Semgrep (cần Docker, lần đầu tải rule hơi lâu)</label>
    </div>
    <div class="opts" style="margin-top:-6px">
      <input id="trivy" type="checkbox">
      <label for="trivy" style="margin:0">Quét hạ tầng: cấu hình triển khai + SBOM (cần Docker)</label>
    </div>
    <button id="go">Bắt đầu quét</button>
    <div class="hint">Không sửa gì trong repo. Kết quả ghi vào thư mục <code>reports/</code>.</div>
  </div>

  <div class="card hidden" id="progress">
    <div class="status" id="status"></div>
    <div class="log" id="log"></div>
  </div>

  <iframe class="hidden" id="frame" title="Báo cáo"></iframe>
</div>
<script>
const $ = id => document.getElementById(id);
let jobId = null, timer = null;

$('go').onclick = async () => {
  const repo = $('repo').value.trim();
  if (!repo) { $('repo').focus(); return; }
  const title = $('title').value.trim() || repo.split(/[\\\\/]/).filter(Boolean).pop();
  $('go').disabled = true;
  $('progress').classList.remove('hidden');
  $('frame').classList.add('hidden');
  $('log').textContent = '';
  const r = await fetch('/scan', { method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ repo, title, sast: $('sast').checked,
                           base_url: $('base').value.trim(),
                           trivy: $('trivy').checked }) });
  jobId = (await r.json()).id;
  timer = setInterval(poll, 700);
};

async function poll() {
  const j = await (await fetch('/status?id=' + jobId)).json();
  $('log').innerHTML = j.log.map(l =>
    `<span class="t">${l.t}</span>  <span class="${l.k}">${esc(l.m)}</span>`).join('\\n');
  $('log').scrollTop = $('log').scrollHeight;
  $('status').innerHTML = j.done ? (j.error ? '' : 'Hoàn tất.')
    : `<span class="spin"></span>${j.step || 'Đang chạy...'}`;
  if (j.done) {
    clearInterval(timer);
    $('go').disabled = false;
    if (j.report) {
      $('frame').src = '/reports/' + j.report + '?t=' + Date.now();
      $('frame').classList.remove('hidden');
      $('frame').scrollIntoView({ behavior:'smooth' });
    }
  }
}
const esc = s => s.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
</script></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif u.path == "/status":
            jid = parse_qs(u.query).get("id", [""])[0]
            self._send(200, json.dumps(JOBS.get(jid, {"log": [], "done": True,
                                                      "error": "khong tim thay job"})).encode(),
                       "application/json")
        elif u.path.startswith("/reports/"):
            f = REPORTS / Path(u.path).name
            if f.exists() and f.suffix == ".html":
                self._send(200, f.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(404, b"khong tim thay", "text/plain")
        else:
            self._send(404, b"khong tim thay", "text/plain")

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/scan":
            self._send(404, b"", "text/plain")
            return
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        jid = uuid.uuid4().hex[:12]
        JOBS[jid] = {"log": [], "done": False, "report": None, "error": None, "step": ""}
        threading.Thread(
            target=run_scan,
            args=(jid, req.get("repo", ""), req.get("title", "Repo"),
                  bool(req.get("sast", True)), req.get("base_url", "").strip(),
                  bool(req.get("trivy", False))),
            daemon=True,
        ).start()
        self._send(200, json.dumps({"id": jid}).encode(), "application/json")

    def log_message(self, *a) -> None:  # tat log mac dinh cho console gon
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    url = f"http://localhost:{args.port}"
    print(f"Giao dien quet dang chay tai {url}")
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
