#!/usr/bin/env python3
"""
Sinh routes_map.json tu ma nguon ASP.NET Core - ca MVC Controller lan Razor Pages.

Vai tro trong do an: thay cho Roslyn. Semgrep bao loi o (tep, dong);
script nay cho biet dong do thuoc endpoint nao, tu do dung ra URL va tham so
de OWASP ZAP ban payload vao dung cho.

NGUYEN TAC: script PHAI tu bao cao nhung truong hop no khong xu ly duoc, thay vi
im lang sinh URL sai. Mot ban do sai nguy hiem hon khong co ban do, vi DAST se
quet nham cho roi bao "khong tim thay lo hong".

Hai quy uoc dinh tuyen:
  Controller : /<Controller>/<Action>, hoac theo [Route] neu co
  Razor Page : duong dan tep chinh la URL
               Pages/Basket/Checkout.cshtml      -> /Basket/Checkout
               Pages/Index.cshtml                -> /
               Areas/Identity/Pages/Account/Login.cshtml -> /Identity/Account/Login

Phan loai moi endpoint:
    testable    - GET, khong tham so duong dan, khong yeu cau dang nhap
    path_param  - route co {placeholder} tren duong dan
    needs_auth  - co [Authorize]
    non_get     - POST/PUT/DELETE
    no_param    - khong co tham so kieu don gian de tan cong

Cach dung:
    python tools/gen_routes_map.py --root . --base-url http://localhost:5000
    python tools/gen_routes_map.py --root ..\\eShopOnWeb --out eshop_routes.json
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

# ---- Controller ----
SIGNATURE = re.compile(
    r"^\s*public\s+(?:async\s+)?"
    r"(?:IActionResult|Task<IActionResult>|ActionResult(?:<[^>]+>)?|"
    r"Task<ActionResult(?:<[^>]+>)?>|string|ContentResult|Task<IResult>|IResult)\s+"
    r"(?P<action>\w+)\s*\((?P<params>[^)]*)\)"
)
CLASS_DECL = re.compile(
    r"^\s*(?:public\s+)?(?:sealed\s+|abstract\s+|partial\s+)*class\s+(?P<name>\w*Controller)\b")

# ---- Razor Page ----
HANDLER = re.compile(
    r"^\s*public\s+(?:async\s+)?\S[^(]*?\bOn(?P<verb>Get|Post|Put|Delete|Head)"
    r"(?P<rest>[A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)")
PAGE_MODEL_CLASS = re.compile(r"^\s*(?:public\s+)?(?:sealed\s+|partial\s+)*class\s+\w+\s*:")
PAGE_DIRECTIVE = re.compile(r'^\s*@page\s+"([^"]*)"')

# ---- chung ----
PARAM = re.compile(
    r"(?:^|,)\s*(?:\[[^\]]*\]\s*)?(?P<type>[\w<>\[\]\.]+\??)\s+(?P<name>\w+)\s*(?:=[^,]+)?")
ATTR_ROUTE = re.compile(r'\[\s*Route\s*\(\s*"([^"]*)"')
ATTR_HTTP = re.compile(r'\[\s*Http(Get|Post|Put|Delete|Patch|Head)\s*(?:\(\s*"([^"]*)"\s*\))?')
ATTR_AUTHORIZE = re.compile(r"\[\s*Authorize\b")
ATTR_ANONYMOUS = re.compile(r"\[\s*AllowAnonymous\b")
PLACEHOLDER = re.compile(r"\{[^}]+\}")

# Kieu gan truc tiep tu query string. Model phuc hop khong nam trong day:
# `OnGet(CatalogIndexViewModel m, int? pageId)` thi tham so that la pageId,
# con `m` la object duoc binding tu nhieu truong - khong ban payload thang vao duoc.
SIMPLE_TYPES = {
    "string", "int", "long", "short", "byte", "bool", "guid", "decimal",
    "double", "float", "datetime", "dateonly", "char",
}


def parse_params(raw: str) -> list[dict]:
    raw = raw.strip()
    if not raw:
        return []
    out = []
    for m in PARAM.finditer(raw):
        t = m.group("type").rstrip("?").lower()
        out.append({"name": m.group("name"), "type": m.group("type"),
                    "simple": t in SIMPLE_TYPES})
    return out


def simple_params(params: list[dict]) -> list[dict]:
    return [p for p in params if p["simple"]]


def simple_names(params: list[dict]) -> list[str]:
    return [p["name"] for p in simple_params(params)]


NUMERIC_TYPES = {"int", "long", "short", "byte", "decimal", "double", "float"}


def guess_seed(params: list[dict]) -> str:
    """Gia tri mo dau cho tham so dau tien - chon theo KIEU, khong doan theo ten.

    Vi sao phai dung: DAST ket luan bang cach so sanh phan hoi cua yeu cau goc
    voi phan hoi khi da chen payload. Neu yeu cau goc da tra ve trang loi - vi
    du gui `pageId=a` vao tham so `int?` thi ASP.NET khong ep kieu duoc - thi
    moc so sanh hong, va moi ket luan sau do deu vo nghia. Day dung la loi da
    gap: seed sai tung lam toan bo SQLi khong bao gio duoc xac nhan.
    """
    if not params:
        return ""
    p = params[0]
    t = p["type"].rstrip("?").lower()
    if t in NUMERIC_TYPES:
        return "1"
    if t == "bool":
        return "true"
    if t == "guid":
        return "00000000-0000-0000-0000-000000000000"
    if t in ("datetime", "dateonly"):
        return "2024-01-01"
    # Con lai la chuoi. Ten van co gia tri goi y: `string id` la chuoi ve kieu
    # nhung mang y nghia so - va chinh viec khai bao chuoi cho mot khoa so la
    # dau hieu cua noi chuoi SQL. Gui "a" vao do sinh ra `WHERE Id = a` -> loi
    # SQL ngay tu yeu cau goc, hong moc so sanh.
    if re.search(r"id$|^id", p["name"], re.I):
        return "1"
    return "a"


def attrs_above(lines: list[str], idx: int) -> str:
    out, i = [], idx - 1
    while i >= 0:
        s = lines[i].strip()
        if not s or s.startswith("//") or s.startswith("///"):
            i -= 1
            continue
        if s.startswith("["):
            out.append(s)
            i -= 1
            continue
        break
    return " ".join(out)


def find_body_end(lines: list[str], start_idx: int) -> int:
    if "=>" in lines[start_idx] and "{" not in lines[start_idx]:
        return start_idx
    depth, seen = 0, False
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth == 0:
                    return i
    return len(lines) - 1


def expand(template: str, controller: str, action: str) -> str:
    return (template.replace("[controller]", controller)
                    .replace("[action]", action).replace("[area]", ""))


def classify(r: dict) -> str:
    if r["needs_auth"]:
        return "needs_auth"
    if r["http_method"] != "GET":
        return "non_get"
    if r["has_path_placeholder"]:
        return "path_param"
    if not r["params"]:
        return "no_param"
    return "testable"


# --------------------------------------------------------------------------
def scan_controller(path: Path, root: Path) -> list[dict]:
    controller = path.stem[:-len("Controller")] if path.stem.endswith("Controller") else path.stem
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    class_route, class_auth = None, False
    for i, line in enumerate(lines):
        if CLASS_DECL.match(line):
            blob = attrs_above(lines, i)
            m = ATTR_ROUTE.search(blob)
            class_route = m.group(1) if m else None
            class_auth = bool(ATTR_AUTHORIZE.search(blob))
            break

    routes = []
    for idx, line in enumerate(lines):
        m = SIGNATURE.match(line)
        if not m:
            continue
        action = m.group("action")
        params = parse_params(m.group("params"))
        blob = attrs_above(lines, idx)

        http = ATTR_HTTP.search(blob)
        method = http.group(1).upper() if http else "GET"
        tpl = http.group(2) if http and http.group(2) else None
        ra = ATTR_ROUTE.search(blob)
        if ra:
            tpl = ra.group(1)

        if class_route or tpl:
            source = "attribute"
            base = expand(class_route or "", controller, action)
            tail = expand(tpl or "", controller, action)
            url = "/" + "/".join(p for p in (base.strip("/"), tail.strip("/")) if p)
        else:
            source = "conventional"
            url = f"/{controller}/{action}"

        names = simple_names(params)
        r = {
            "kind": "controller",
            "controller": controller, "action": action,
            "file": path.relative_to(root).as_posix(),
            "line_start": idx + 1, "line_end": find_body_end(lines, idx) + 1,
            "url_path": re.sub(r"/{2,}", "/", url),
            "method": method, "http_method": method,
            "route_source": source,
            "needs_auth": class_auth and not ATTR_ANONYMOUS.search(blob),
            "has_path_placeholder": bool(PLACEHOLDER.search(url)),
            "params": names,
            "all_params": [p["name"] for p in params],
            "test_seed": guess_seed(simple_params(params)),
        }
        r["status"] = classify(r)
        routes.append(r)
    return routes


def razor_url(model_path: Path, root: Path) -> str | None:
    """Duong dan tep -> URL, theo quy uoc dinh tuyen cua Razor Pages."""
    parts = list(model_path.relative_to(root).parts)
    if "Pages" not in parts:
        return None
    i = len(parts) - 1 - parts[::-1].index("Pages")
    area = parts[i - 1] if i >= 2 and parts[i - 2] == "Areas" else None

    tail = parts[i + 1:]
    if not tail:
        return None
    tail = list(tail)
    tail[-1] = re.sub(r"\.cshtml(\.cs)?$", "", tail[-1])
    if tail[-1].lower() == "index":
        tail.pop()

    segs = ([area] if area else []) + tail
    return "/" + "/".join(segs) if segs else "/"


def scan_razor_page(model_path: Path, root: Path) -> list[dict]:
    """Quet mot PageModel (*.cshtml.cs) va lay cac handler OnGet/OnPost."""
    url = razor_url(model_path, root)
    if url is None:
        return []

    lines = model_path.read_text(encoding="utf-8", errors="replace").splitlines()

    # [Authorize] tren lop PageModel
    class_auth = False
    for i, line in enumerate(lines):
        if PAGE_MODEL_CLASS.match(line) and "PageModel" in line:
            class_auth = bool(ATTR_AUTHORIZE.search(attrs_above(lines, i)))
            break

    # Chi thi @page trong file .cshtml anh em co the them tham so duong dan
    page_tpl = ""
    view = model_path.with_suffix("")          # bo .cs -> con .cshtml
    if view.exists():
        for line in view.read_text(encoding="utf-8", errors="replace").splitlines()[:8]:
            m = PAGE_DIRECTIVE.match(line)
            if m:
                page_tpl = m.group(1)
                break

    full_url = re.sub(r"/{2,}", "/", f"{url}/{page_tpl.strip('/')}" if page_tpl else url)

    routes = []
    for idx, line in enumerate(lines):
        m = HANDLER.match(line)
        if not m:
            continue
        verb = m.group("verb").upper()
        rest = m.group("rest")
        named = rest[:-5] if rest.endswith("Async") else rest
        params = parse_params(m.group("params"))
        names = simple_names(params)

        u = full_url
        if named:                       # handler co ten -> ?handler=Ten
            u = f"{full_url}?handler={named}"

        r = {
            "kind": "razor_page",
            "controller": model_path.parent.name, "action": f"On{verb}{named}",
            "file": model_path.relative_to(root).as_posix(),
            "line_start": idx + 1, "line_end": find_body_end(lines, idx) + 1,
            "url_path": u,
            "method": verb, "http_method": verb,
            "route_source": "razor_convention",
            "needs_auth": class_auth and not ATTR_ANONYMOUS.search(attrs_above(lines, idx)),
            "has_path_placeholder": bool(PLACEHOLDER.search(full_url)),
            "params": names,
            "all_params": [p["name"] for p in params],
            "test_seed": guess_seed(simple_params(params)),
        }
        r["status"] = classify(r)
        routes.append(r)
    return routes


# --------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--base-url", default="http://localhost:5000")
    ap.add_argument("--out", default="routes_map.json")
    ap.add_argument("--no-razor", action="store_true", help="bo qua Razor Pages")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    skip = lambda f: "bin" in f.parts or "obj" in f.parts  # noqa: E731

    ctrl_files = [f for f in sorted(root.rglob("*Controller.cs")) if not skip(f)]
    page_files = ([] if args.no_razor else
                  [f for f in sorted(root.rglob("*.cshtml.cs")) if not skip(f)])
    if not ctrl_files and not page_files:
        # "Quet roi, khong co gi" KHAC "khong quet duoc". Truoc day cho nay
        # thoat voi ma 1, nen mot repo khong phai .NET - hoac repo chi chua bo
        # cong cu - lam ca pipeline do, dung nhu the co su co. Khong phai: day
        # la mot ket qua hop le, va no bang 0.
        #
        # Van ghi ra tep ban do rong de buoc dung bao cao phia sau co cai de
        # doc, va de bang ket qua hien "0/0" thay vi bien mat khong giai thich.
        print(f"Khong co Controller hay Razor Page nao duoi {root}.")
        print("Day la ket qua hop le (0 endpoint), khong phai loi: repo nay")
        print("khong chua ung dung ASP.NET. Ghi ban do rong va di tiep.")
        Path(args.out).write_text(json.dumps({
            "app_base_url": args.base_url,
            "generated_from": {"controllers": 0, "razor_pages": 0},
            "summary": {},
            "by_kind": {},
            "routes": [],
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        return

    routes = []
    for f in ctrl_files:
        routes.extend(scan_controller(f, root))
    for f in page_files:
        routes.extend(scan_razor_page(f, root))

    tally = Counter(r["status"] for r in routes)
    by_kind = Counter(r["kind"] for r in routes)
    testable = [r for r in routes if r["status"] == "testable"]

    Path(args.out).write_text(json.dumps({
        "app_base_url": args.base_url,
        "generated_from": {"controllers": len(ctrl_files), "razor_pages": len(page_files)},
        "summary": dict(tally),
        "by_kind": dict(by_kind),
        "routes": routes,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Quet {len(ctrl_files)} controller + {len(page_files)} Razor Page "
          f"-> {len(routes)} endpoint")
    print(f"  controller: {by_kind['controller']}   razor page: {by_kind['razor_page']}\n")

    labels = {
        "testable":   "DAST kiem thu duoc ngay",
        "path_param": "Tham so nam tren duong dan",
        "needs_auth": "Yeu cau dang nhap",
        "non_get":    "Khong phai GET",
        "no_param":   "Khong co tham so kieu don gian",
    }
    for k in ("testable", "path_param", "needs_auth", "non_get", "no_param"):
        if tally[k]:
            print(f"  {tally[k]:>3}  {k:<12} {labels[k]}")

    pct = len(testable) / len(routes) * 100 if routes else 0
    print(f"\nTi le kiem thu duoc bang DAST: {len(testable)}/{len(routes)} = {pct:.0f}%")
    if testable:
        print("\nCac endpoint kiem thu duoc:")
        for r in testable:
            p = r["params"][0]
            print(f"  {r['url_path']:<42} {p}={r['test_seed']:<4} ({r['kind']})")
    print(f"\nDa ghi {args.out}")


if __name__ == "__main__":
    main()
