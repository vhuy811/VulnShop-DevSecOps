#!/usr/bin/env python3
"""
Sinh bao cao HTML tu ket qua quet - tang nhin duoc cua cong cu.

Doc ba nguon, nguon nao thieu thi bo qua:
    reports/sca_*.json        tang SCA  (thu vien -> CVE)
    reports/semgrep_*.sarif   tang SAST (ma nguon -> CWE)
    reports/routes_*.json     pham vi ap dung (endpoint nao DAST cham toi duoc)
    reports/findings.json     ket qua da gan 3 nhan (neu co chay DAST)

Cach dung:
    python tools/report.py --title "eShopOnWeb" \\
        --sca reports/sca_eshop.json \\
        --sast reports/semgrep_eshop.sarif \\
        --routes reports/routes_eshop.json \\
        --out reports/bao_cao_eshop.html
"""
from __future__ import annotations

import argparse
import html
import json
import re
from datetime import date
from pathlib import Path

# Bang mau trang thai - co dinh, khong doi theo theme.
# Low KHONG dung mau trang thai "good": muc do thap van la lo hong, khong phai
# tin tot. No mang mau muc de khong gia vo an toan.
SEV = {
    "Critical": ("critical", "#d03b3b", "◆"),
    "High":     ("serious",  "#ec835a", "▲"),
    "Moderate": ("warning",  "#fab219", "●"),
    "Low":      ("muted",    "#898781", "○"),
}
SEV_ORDER = ["Critical", "High", "Moderate", "Low"]
CWE_RE = re.compile(r"CWE-\d+")


def esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def load_json(p: str | None):
    if not p:
        return None
    path = Path(p)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def load_sast(p: str | None) -> list[dict]:
    doc = load_json(p)
    if not doc:
        return []
    out = []
    for run in doc.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            msg = res.get("message", {}).get("text", "")
            rid = res.get("ruleId", "")
            blob = msg + " " + json.dumps(rules.get(rid, {}))
            m = CWE_RE.search(blob)
            out.append({
                "rule": rid.split(".")[-1],
                "cwe": m.group(0) if m else "—",
                "file": loc.get("artifactLocation", {}).get("uri", ""),
                "line": loc.get("region", {}).get("startLine", 0),
                "message": msg.strip().split("\n")[0],
                "level": res.get("level", "warning"),
            })
    return out


def tile(label: str, value, note: str = "") -> str:
    return (f'<div class="tile"><div class="tile-l">{esc(label)}</div>'
            f'<div class="tile-v">{esc(value)}</div>'
            f'<div class="tile-n">{esc(note)}</div></div>')


def severity_bar(counts: dict) -> str:
    """Mot thanh chong lop: phan cua mot tong. Co nhan truc tiep, khong dua vao mau."""
    total = sum(counts.values())
    if not total:
        return ""
    segs, chips = [], []
    for s in SEV_ORDER:
        n = counts.get(s, 0)
        if not n:
            continue
        _, hexv, icon = SEV[s]
        segs.append(f'<div class="seg" style="flex:{n};background:{hexv}" '
                    f'title="{s}: {n}"></div>')
        chips.append(f'<span class="chip"><span class="dot" style="background:{hexv}">'
                     f'</span>{icon} {s} <b>{n}</b></span>')
    return (f'<div class="bar">{"".join(segs)}</div>'
            f'<div class="chips">{"".join(chips)}</div>')


def sca_section(sca: dict | None) -> str:
    if not sca:
        return ""
    f = sca["findings"]
    rows = []
    for x in sorted(f, key=lambda y: (-SEV_ORDER[::-1].index(y["severity"]), y["package"])):
        _, hexv, icon = SEV[x["severity"]]
        links = " ".join(
            f'<a href="{esc(u)}" target="_blank" rel="noopener">{esc(u.rsplit("/", 1)[-1])}</a>'
            for u in x["advisories"])
        origin = ("khai báo trực tiếp" if x["dependency"] == "top"
                  else "thư viện của thư viện")
        rows.append(
            f'<tr><td><code>{esc(x["package"])}</code></td>'
            f'<td class="num">{esc(x["version"])}</td>'
            f'<td><span class="dot" style="background:{hexv}"></span>{icon} {esc(x["severity"])}</td>'
            f'<td>{esc(origin)}</td><td class="adv">{links}</td></tr>')
    return f"""
    <section>
      <h2>Tầng 1 — Thư viện <span class="sub">đối chiếu GitHub Advisory Database / CVE</span></h2>
      <p class="lead">Tầng này <b>không suy đoán</b>. Nó so phiên bản thư viện với cơ sở dữ liệu
      lỗ hổng đã công bố: trùng thì trùng. Không có dương tính giả theo nghĩa của hai tầng kia.</p>
      {severity_bar(sca["summary"]["by_severity"])}
      <table>
        <thead><tr><th>Gói</th><th>Phiên bản</th><th>Mức độ</th>
        <th>Nguồn gốc</th><th>Advisory</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
      <p class="note"><b>{sca["summary"]["transitive"]}/{sca["summary"]["packages"]} gói là
      thư viện của thư viện</b> — lập trình viên không chủ động chọn, không thấy trong
      <code>.csproj</code>. Chỉ quét phụ thuộc mới phát hiện ra.</p>
    </section>"""


def sast_section(sast: list[dict], rules_note: str) -> str:
    if not sast:
        body = '<p class="empty">Không có cảnh báo nào từ bộ rule đã dùng.</p>'
    else:
        rows = "".join(
            f'<tr><td><code>{esc(x["file"])}:{x["line"]}</code></td>'
            f'<td>{esc(x["cwe"])}</td><td><code>{esc(x["rule"])}</code></td>'
            f'<td>{esc(x["message"][:110])}</td></tr>' for x in sast)
        body = (f'<table><thead><tr><th>Vị trí</th><th>CWE</th><th>Rule</th>'
                f'<th>Mô tả</th></tr></thead><tbody>{rows}</tbody></table>')
    return f"""
    <section>
      <h2>Tầng 2 — Mã nguồn <span class="sub">phân tích tĩnh, phân loại theo CWE</span></h2>
      <p class="lead">Tầng này khớp <b>hình dạng code</b> với mẫu mô tả trong rule.
      Nó chỉ tìm được thứ đã có người mô tả thành rule, và có thể báo nhầm. {esc(rules_note)}</p>
      {body}
    </section>"""


def scope_section(routes: dict | None) -> str:
    if not routes:
        return ""
    s = routes.get("summary", {})
    total = sum(s.values()) or 1
    testable = s.get("testable", 0)
    labels = {
        "testable":   "Kiểm thử động được ngay",
        "needs_auth": "Yêu cầu đăng nhập — ngoài phạm vi đồ án",
        "path_param": "Tham số nằm trên đường dẫn, không phải query string",
        "non_get":    "Không phải GET",
        "no_param":   "Không có tham số để tấn công",
    }
    rows = "".join(
        f'<tr><td>{esc(labels.get(k, k))}</td><td class="num">{v}</td>'
        f'<td class="num">{v / total * 100:.0f}%</td></tr>'
        for k, v in sorted(s.items(), key=lambda kv: -kv[1]) if v)
    pct = testable / total * 100
    tone = "ok" if pct >= 50 else ("warn" if pct > 0 else "bad")
    return f"""
    <section>
      <h2>Tầng 3 — Phạm vi áp dụng của kiểm thử động</h2>
      <p class="lead">Không phải endpoint nào cũng kiểm thử động được. Bảng này đo
      <b>giới hạn của chính công cụ</b> thay vì giấu đi — một bản đồ sai còn nguy hiểm
      hơn không có bản đồ.</p>
      <div class="scope {tone}">{testable}/{total} endpoint kiểm thử được ({pct:.0f}%)</div>
      <table><thead><tr><th>Tình trạng</th><th>Số lượng</th><th>Tỉ lệ</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </section>"""


LABEL = {
    "CONFIRMED":   ("#d03b3b", "◆", "Đã xác nhận khai thác được"),
    "UNCONFIRMED": ("#898781", "○", "Chưa có bằng chứng theo chiều nào"),
    "FILTERED":    ("#0ca30c", "✓", "Có bằng chứng loại trừ"),
}
LABEL_ORDER = ["CONFIRMED", "UNCONFIRMED", "FILTERED"]


def cap_so_sanh(cmp_: dict) -> tuple[dict, dict]:
    """Lay cap (truoc, sau) tu ket qua so sanh image.

    Van doc duoc khoa cu gan cung ten image, de bao cao sinh lai tu tep ket
    qua cu khong bi trong.
    """
    a = cmp_.get("truoc") or cmp_.get("vulnshop:naive") or {}
    b = cmp_.get("sau") or cmp_.get("vulnshop:hardened") or {}
    return a, b


def dast_section(dast: dict | None) -> str:
    """Tang 4 - trai tim cua do an: doi sanh tinh x dong roi gan ba nhan."""
    if not dast:
        return ""
    s = dast.get("summary", {})
    total = sum(s.values())
    if not total:
        return ""

    segs, chips = [], []
    for k in LABEL_ORDER:
        n = s.get(k, 0)
        if not n:
            continue
        hexv, icon, _ = LABEL[k]
        segs.append(f'<div class="seg" style="flex:{n};background:{hexv}" title="{k}: {n}"></div>')
        chips.append(f'<span class="chip"><span class="dot" style="background:{hexv}"></span>'
                     f'{icon} {k} <b>{n}</b></span>')

    co_baseline = dast.get("baseline_used", False)
    rows = []
    order = {k: i for i, k in enumerate(LABEL_ORDER)}
    for x in sorted(dast.get("results", []),
                    key=lambda y: (order.get(y.get("label"), 9),
                                   not y.get("moi", True), y.get("file", ""), y.get("line", 0))):
        hexv, icon, _ = LABEL.get(x.get("label", ""), ("#898781", "○", ""))
        target = (f'<code>{esc(x.get("url", ""))}</code>'
                  f'<span class="muted">?{esc(x.get("param", ""))}=</span>'
                  if x.get("url") else '<span class="muted">không ánh xạ được</span>')
        # Nhan "no cu" chi co y nghia khi co baseline. Khong co baseline thi
        # khong biet cai nao cu - va khong duoc doan.
        tag_cu = ('<span class="tag-cu">nợ cũ</span>'
                  if co_baseline and not x.get("moi", True) else "")
        rows.append(
            f'<tr><td><span class="dot" style="background:{hexv}"></span>{icon} '
            f'<b>{esc(x.get("label"))}</b>{tag_cu}</td>'
            f'<td class="nw">{esc(x.get("cwe", "—"))}</td>'
            f'<td><code>{esc(x.get("file", ""))}:{x.get("line", 0)}</code></td>'
            f'<td>{target}</td>'
            f'<td class="ev">{esc(x.get("evidence", ""))}</td></tr>')

    rate = dast.get("resolution_rate", 0) * 100
    n_unc = s.get("UNCONFIRMED", 0)

    # Khoi baseline: noi ro cong chan cai gi va KHONG chan cai gi.
    n_moi = dast.get("confirmed_new", s.get("CONFIRMED", 0))
    n_cu = dast.get("confirmed_old", 0)
    if co_baseline:
        baseline_note = (
            f'<div class="scope {"warn" if n_moi else "ok"}">Baseline so với nhánh gốc: '
            f'<b>{n_moi} CONFIRMED mới</b> do lần thay đổi này đưa vào'
            + (f', <b>{n_cu} CONFIRMED là nợ cũ</b> từ trước — được báo cáo đầy đủ nhưng '
               f'không chặn merge của người không gây ra nó' if n_cu else '')
            + '. Cổng chỉ chặn phần mới.</div>')
    else:
        baseline_note = ('<div class="scope warn">Không có mốc baseline (quét định kỳ, chạy tay, '
                         'hoặc nhánh vừa tạo) — mọi cảnh báo đều tính là mới.</div>')

    n_ngoai = dast.get("outside_dast_scope", 0)
    ngoai_note = (f'<p class="note">{n_ngoai} cảnh báo thuộc CWE mà ZAP <b>không có active '
                  f'scan rule</b> — không kiểm chứng động được, không tính vào cổng, '
                  f'cần review tay.</p>' if n_ngoai else "")
    return f"""
    <section>
      <h2>Tầng 4 — Đối sánh tĩnh × động <span class="sub">gán ba nhãn cho từng cảnh báo</span></h2>
      <p class="lead">Ba tầng trên đều trả lời một nửa câu hỏi. Tầng này ghép lại:
      mỗi cảnh báo tĩnh được đem ra kiểm chứng trên ứng dụng đang chạy.
      Nguyên tắc chi phối toàn bộ bảng dưới đây là
      <b>“im lặng không phải là bằng chứng”</b> — scanner không tìm thấy gì
      <i>không</i> đồng nghĩa với an toàn, nên mặc định là UNCONFIRMED chứ không
      phải “đã sạch”.</p>
      <div class="bar">{"".join(segs)}</div>
      <div class="chips">{"".join(chips)}</div>
      <div class="scope {"ok" if rate >= 50 else "warn"}">Tỉ lệ phân giải
        {rate:.0f}% — {total - n_unc}/{total} cảnh báo có bằng chứng theo một chiều</div>
      {baseline_note}
      <table>
        <thead><tr><th>Nhãn</th><th>CWE</th><th>Vị trí trong mã</th>
        <th>Điểm kiểm thử</th><th>Bằng chứng</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
      <p class="note"><b>FILTERED không phải “đã sửa”</b> mà là “có bằng chứng tĩnh
      loại trừ” — tìm thấy hàm khử độc nằm trên đúng luồng dữ liệu đó. Còn
      <b>UNCONFIRMED là nợ kiểm thử</b>, không phải kết luận an toàn: {n_unc} cảnh
      báo vẫn đang chờ được chứng minh hoặc bác bỏ.</p>
      {ngoai_note}
    </section>"""


def trivy_section(tv: dict | None) -> str:
    """Tang 5 - thu ma ba tang kia mu hoan toan: image va cau hinh trien khai."""
    if not tv:
        return ""
    parts = []

    cmp_ = tv.get("compare") or {}
    if len(cmp_) == 2:
        a, b = cap_so_sanh(cmp_)
        ta, tb = a.get("total", 0), b.get("total", 0)
        cut = (ta - tb) / ta * 100 if ta else 0
        rows = "".join(
            f'<tr><td><span class="dot" style="background:{SEV[lbl][1]}"></span>{SEV[lbl][2]} {lbl}</td>'
            f'<td class="num">{a.get("by_severity", {}).get(sev, 0)}</td>'
            f'<td class="num">{b.get("by_severity", {}).get(sev, 0)}</td>'
            f'<td class="num">{a.get("by_severity", {}).get(sev, 0) - b.get("by_severity", {}).get(sev, 0)}</td></tr>'
            for sev, lbl in (("CRITICAL", "Critical"), ("HIGH", "High"),
                             ("MEDIUM", "Moderate"), ("LOW", "Low"))
            if a.get("by_severity", {}).get(sev, 0) or b.get("by_severity", {}).get(sev, 0))
        parts.append(f"""
      <h3>Trước và sau khi gia cố image</h3>
      <table><thead><tr><th>Mức độ</th><th>Ngây thơ</th><th>Đã gia cố</th><th>Giảm</th></tr></thead>
      <tbody>{rows}
        <tr><td><b>Tổng</b></td><td class="num"><b>{ta}</b></td>
        <td class="num"><b>{tb}</b></td><td class="num"><b>{ta - tb}</b></td></tr>
      </tbody></table>
      <p class="note">Giảm <b>{cut:.0f}%</b> số CVE mà <b>không sửa một dòng mã ứng dụng nào</b> —
      chỉ đổi image nền từ <code>sdk</code> sang <code>aspnet</code> và bỏ quyền root.
      Đây là phần lỗ hổng mà SAST, DAST và SCA đều không nhìn thấy: chúng đọc mã nguồn
      ứng dụng, còn số này nằm trong các gói hệ điều hành đi kèm image.</p>""")

    cfg = tv.get("config") or {}
    if cfg.get("issues"):
        rows = "".join(
            f'<tr><td><code>{esc(i["target"])}:{i["line"]}</code></td>'
            f'<td>{esc(i["severity"])}</td><td><code>{esc(i["id"])}</code></td>'
            f'<td>{esc(i["title"])}</td></tr>'
            for i in sorted(cfg["issues"],
                            key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
                            .index(x["severity"]))[:15])
        parts.append(f"""
      <h3>Lỗi cấu hình triển khai <span class="sub">{cfg.get("total", 0)} phát hiện</span></h3>
      <table><thead><tr><th>Vị trí</th><th>Mức</th><th>Mã kiểm tra</th><th>Nội dung</th></tr></thead>
      <tbody>{rows}</tbody></table>""")

    sb = tv.get("sbom") or {}
    if sb.get("components"):
        parts.append(f"""
      <p class="note"><b>SBOM: {sb["components"]} thành phần</b> (định dạng CycloneDX,
      tệp <code>{esc(sb.get("file", ""))}</code>). Danh mục thành phần nay là yêu cầu
      bắt buộc với phần mềm bán cho chính phủ Mỹ và trong Đạo luật An ninh mạng của EU.</p>""")

    if not parts:
        return ""
    return f"""
    <section>
      <h2>Tầng 5 — Hạ tầng <span class="sub">container image và cấu hình triển khai</span></h2>
      <p class="lead">Bốn tầng trên chỉ nhìn thấy <b>mã nguồn ứng dụng</b>. Nhưng ứng dụng
      thật không chạy trần trên máy — nó chạy trong container, trên một hệ điều hành có
      hàng trăm gói riêng. Phần đó thường chứa nhiều lỗ hổng hơn chính mã ứng dụng.</p>
      {"".join(parts)}
    </section>"""


def build(title: str, sca, sast, routes, rules_note: str, dast=None, trivy=None) -> str:
    n_pkg = sca["summary"]["packages"] if sca else 0
    n_adv = sca["summary"]["advisories"] if sca else 0
    n_trans = sca["summary"]["transitive"] if sca else 0
    n_code = len(sast)
    total = n_adv + n_code

    # Nhan bo rule suy ra tu chinh du lieu SARIF thay vi ghi chet:
    # moi rule rieng cua do an deu co tien to "vulnshop-".
    n_own = sum(1 for r in sast if r.get("rule", "").startswith("vulnshop-"))
    if not sast:
        rules_src = "chưa có cảnh báo nào"
    elif n_own == len(sast):
        rules_src = "từ bộ rule riêng của đồ án"
    elif n_own:
        rules_src = f"{n_own}/{len(sast)} từ bộ rule riêng của đồ án"
    else:
        rules_src = "từ bộ rule cộng đồng"

    rs = routes.get("summary", {}) if routes else {}
    r_total = sum(rs.values())
    r_ok = rs.get("testable", 0)

    ds = dast.get("summary", {}) if dast else {}
    n_conf = ds.get("CONFIRMED", 0)
    n_filt = ds.get("FILTERED", 0)
    n_unc = ds.get("UNCONFIRMED", 0)

    tv_total = 0
    if trivy:
        cmp_ = trivy.get("compare") or {}
        tv_total = cap_so_sanh(cmp_)[0].get("total", 0) \
            or (trivy.get("image") or {}).get("total", 0)

    layers = ["thư viện", "mã nguồn", "phạm vi kiểm thử động"]
    if dast:
        layers.append("đối sánh 3 nhãn")
    if trivy:
        layers.append("hạ tầng")

    # O thu tu: neu da chay DAST thi con so dang gia nhat la so da XAC NHAN
    # khai thac duoc, khong phai so canh bao tho.
    if dast:
        last_tile = tile("Đã xác nhận khai thác được", n_conf,
                         f"{n_filt} bị loại trừ · {n_unc} chưa rõ")
    elif trivy:
        last_tile = tile("CVE trong container image", tv_total,
                         "gói hệ điều hành đi kèm")
    else:
        last_tile = tile("Mức Critical",
                         sca["summary"]["by_severity"]["Critical"] if sca else 0,
                         "cần xử lý trước tiên")

    return f"""<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Báo cáo quét bảo mật — {esc(title)}</title>
<style>
  :root {{
    color-scheme: light;
    --surface: #fcfcfb; --plane: #f9f9f7;
    --ink: #0b0b0b; --ink2: #52514e; --muted: #898781;
    --grid: #e1e0d9; --ring: rgba(11,11,11,.10);
    --accent: #2a78d6;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      color-scheme: dark;
      --surface: #1a1a19; --plane: #0d0d0d;
      --ink: #fff; --ink2: #c3c2b7; --muted: #898781;
      --grid: #2c2c2a; --ring: rgba(255,255,255,.10);
      --accent: #3987e5;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background: var(--plane); color: var(--ink);
    font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }}
  .wrap {{ max-width: 1080px; margin: 0 auto; padding: 32px 16px 72px; }}
  header {{ border-bottom: 1px solid var(--grid); padding-bottom: 20px; margin-bottom: 28px; }}
  h1 {{ font-size: 24px; margin: 0 0 6px; letter-spacing: -.01em; }}
  .meta {{ color: var(--ink2); font-size: 14px; }}
  .hero {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 12px;
    padding: 24px 28px; margin-bottom: 20px; }}
  .hero-v {{ font-size: 52px; font-weight: 640; line-height: 1; letter-spacing: -.02em; }}
  .hero-l {{ color: var(--ink2); margin-top: 8px; }}
  .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 12px; margin-bottom: 28px; }}
  .tile {{ background: var(--surface); border: 1px solid var(--ring);
    border-radius: 10px; padding: 16px 18px; }}
  .tile-l {{ color: var(--ink2); font-size: 13px; }}
  .tile-v {{ font-size: 30px; font-weight: 620; line-height: 1.15; margin-top: 4px; }}
  .tile-n {{ color: var(--muted); font-size: 12px; margin-top: 2px; }}
  section {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 12px;
    padding: 22px 24px; margin-bottom: 20px; }}
  h2 {{ font-size: 18px; margin: 0 0 4px; }}
  .sub {{ font-weight: 400; color: var(--muted); font-size: 14px; }}
  .lead {{ color: var(--ink2); margin: 8px 0 18px; font-size: 14px; }}
  .note {{ color: var(--ink2); font-size: 13.5px; margin-top: 14px;
    border-left: 3px solid var(--accent); padding-left: 12px; }}
  .empty {{ color: var(--muted); font-style: italic; }}
  .bar {{ display: flex; gap: 2px; height: 10px; border-radius: 5px;
    overflow: hidden; margin-bottom: 10px; }}
  .seg {{ min-width: 6px; }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 18px;
    font-size: 13px; color: var(--ink2); }}
  .dot {{ display: inline-block; width: 9px; height: 9px; border-radius: 50%;
    margin-right: 6px; vertical-align: baseline; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
  th {{ text-align: left; font-weight: 600; color: var(--ink2); font-size: 12.5px;
    text-transform: uppercase; letter-spacing: .03em;
    border-bottom: 1px solid var(--grid); padding: 8px 10px 8px 0; }}
  td {{ padding: 9px 10px 9px 0; border-bottom: 1px solid var(--grid);
    vertical-align: top; }}
  .num {{ font-variant-numeric: tabular-nums; }}
  code {{ font: 12.5px ui-monospace, Consolas, monospace; color: var(--ink); }}
  a {{ color: var(--accent); }}
  .adv a {{ display: block; font: 12px ui-monospace, Consolas, monospace; }}
  .scope {{ display: inline-block; font-size: 17px; font-weight: 620;
    padding: 9px 16px; border-radius: 8px; margin-bottom: 16px;
    border: 1px solid var(--ring); }}
  h3 {{ font-size: 15px; margin: 22px 0 10px; }}
  .muted {{ color: var(--muted); }}
  .ev {{ color: var(--ink2); font-size: 12.5px; max-width: 320px; }}
  .chip, .nw {{ white-space: nowrap; }}
  .tag-cu {{ display:inline-block; margin-left:6px; padding:1px 6px; border-radius:3px;
             font-size:11px; font-weight:600; color:#1a1a19; background:#fab219; }}
  .scope.ok   {{ color: #0ca30c; }}
  .scope.warn {{ color: #ec835a; }}
  .scope.bad  {{ color: #d03b3b; }}
  footer {{ color: var(--muted); font-size: 12.5px; margin-top: 8px; }}
  @media (max-width: 640px) {{ .hero-v {{ font-size: 40px; }} .adv a {{ font-size: 11px; }} }}
</style></head><body>
<div class="wrap">
  <header>
    <h1>Báo cáo quét bảo mật — {esc(title)}</h1>
    <div class="meta">Quét ngày {date.today().isoformat()} · {len(layers)} tầng: {", ".join(layers)}</div>
  </header>

  <div class="hero">
    <div class="hero-v">{total + tv_total}</div>
    <div class="hero-l">lỗ hổng phát hiện được — {n_adv} trong thư viện, {n_code} trong mã nguồn{f", {tv_total} trong container image" if tv_total else ""}</div>
  </div>

  <div class="tiles">
    {tile("Gói thư viện dính lỗ hổng", n_pkg, f"{n_trans} gói là phụ thuộc gián tiếp")}
    {tile("Cảnh báo mã nguồn", n_code, rules_src)}
    {tile("Endpoint kiểm thử động được", f"{r_ok}/{r_total}" if r_total else "—",
          "phần còn lại ngoài phạm vi")}
    {last_tile}
  </div>

  {sca_section(sca)}
  {sast_section(sast, rules_note)}
  {scope_section(routes)}
  {dast_section(dast)}
  {trivy_section(trivy)}

  <footer>
    Sinh bởi công cụ quét của đồ án “Xây dựng quy trình DevSecOps tích hợp kiểm thử SAST và DAST”.
    Kết quả tầng thư viện tra cứu được trên NVD qua các liên kết advisory ở trên.
  </footer>
</div>
</body></html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--title", default="Ứng dụng")
    ap.add_argument("--sca")
    ap.add_argument("--sast")
    ap.add_argument("--routes")
    ap.add_argument("--dast", help="findings.json tu correlate.py (ket qua 3 nhan)")
    ap.add_argument("--trivy", help="trivy.json tu trivy.py (image + cau hinh + SBOM)")
    ap.add_argument("--rules-note", default="")
    ap.add_argument("--out", default="reports/bao_cao.html")
    args = ap.parse_args()

    sca = load_json(args.sca)
    sast = load_sast(args.sast)
    routes = load_json(args.routes)
    dast = load_json(args.dast)
    trivy = load_json(args.trivy)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(args.title, sca, sast, routes, args.rules_note, dast, trivy),
                   encoding="utf-8")
    print(f"Da ghi {out}")
    print(f"  Thu vien : {sca['summary']['packages'] if sca else 0} goi, "
          f"{sca['summary']['advisories'] if sca else 0} advisory")
    print(f"  Ma nguon : {len(sast)} canh bao")
    if routes:
        s = routes.get("summary", {})
        print(f"  Pham vi  : {s.get('testable', 0)}/{sum(s.values())} endpoint kiem thu duoc")
    if dast:
        d = dast.get("summary", {})
        print(f"  Doi sanh : CONFIRMED {d.get('CONFIRMED', 0)}  "
              f"FILTERED {d.get('FILTERED', 0)}  UNCONFIRMED {d.get('UNCONFIRMED', 0)}")
    if trivy:
        cmp_ = trivy.get("compare") or {}
        if len(cmp_) == 2:
            a, b = (x.get("total", 0) for x in cap_so_sanh(cmp_))
            print(f"  Ha tang  : image {a} -> {b} CVE sau khi gia co")
        if trivy.get("config"):
            print(f"             {trivy['config']['total']} loi cau hinh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
