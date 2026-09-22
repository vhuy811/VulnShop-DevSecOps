#!/usr/bin/env python3
"""
Sinh routes_map.json tu ma nguon Controller cua ASP.NET Core MVC.

Vai tro trong do an: thay cho Roslyn. Semgrep bao loi o (file, dong);
script nay cho biet dong do nam trong action nao, tu do dung ra URL
va danh sach tham so de OWASP ZAP ban payload vao dung cho.

Cach dung:
    python tools/gen_routes_map.py --root . --base-url http://localhost:5000
"""
import argparse
import json
import re
from pathlib import Path

# public IActionResult Search(string q)
SIGNATURE = re.compile(
    r"^\s*public\s+(?:async\s+)?(?:IActionResult|Task<IActionResult>|ActionResult|string|ContentResult)\s+"
    r"(?P<action>\w+)\s*\((?P<params>[^)]*)\)"
)
# string q  |  int id  |  string? name = null
PARAM = re.compile(r"(?:^|,)\s*(?:\[[^\]]*\]\s*)?[\w<>\[\]?\.]+\s+(?P<name>\w+)\s*(?:=[^,]+)?")


def parse_params(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []
    return [m.group("name") for m in PARAM.finditer(raw)]


def guess_seed(params: list[str]) -> str:
    """
    Doan gia tri moi cho request nen khi kiem thu dong.

    DAST ket luan bang cach SO SANH phan hoi giua cac payload, nen request
    nen PHAI tra ve mot trang binh thuong. Mot gia tri lam app bao loi hoac
    tra ve danh sach rong se pha hong phep so sanh do va lo hong that van
    co the khong bi phat hien.

    Doan sai thi sua tay khoa `test_seed` trong routes_map.json; gia tri
    ghi tay luon duoc uu tien.
    """
    if not params:
        return ""
    if re.search(r"(^|_)id$|^id", params[0], re.I):
        return "1"
    return "a"


def find_body_end(lines: list[str], start_idx: int) -> int:
    """Tra ve chi so dong cuoi cua than method (0-based)."""
    # Expression-bodied:  public IActionResult About() => Content(...);
    if "=>" in lines[start_idx] and "{" not in lines[start_idx]:
        return start_idx

    depth = 0
    seen_brace = False
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                seen_brace = True
            elif ch == "}":
                depth -= 1
                if seen_brace and depth == 0:
                    return i
    return len(lines) - 1


def scan_controller(path: Path, root: Path) -> list[dict]:
    controller = path.stem
    if controller.endswith("Controller"):
        controller = controller[: -len("Controller")]

    lines = path.read_text(encoding="utf-8").splitlines()
    routes = []
    for idx, line in enumerate(lines):
        m = SIGNATURE.match(line)
        if not m:
            continue
        action = m.group("action")
        params = parse_params(m.group("params"))
        end = find_body_end(lines, idx)
        routes.append(
            {
                "controller": controller,
                "action": action,
                "file": path.relative_to(root).as_posix(),
                "line_start": idx + 1,   # 1-based cho khop voi SARIF
                "line_end": end + 1,
                "url_path": f"/{controller}/{action}",
                "method": "GET",
                "params": params,
                "test_seed": guess_seed(params),
            }
        )
    return routes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--base-url", default="http://localhost:5000")
    ap.add_argument("--out", default="routes_map.json")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    files = sorted((root / "Controllers").glob("*Controller.cs"))
    if not files:
        raise SystemExit(f"Khong tim thay Controller nao trong {root / 'Controllers'}")

    routes = []
    for f in files:
        routes.extend(scan_controller(f, root))

    out = {
        "app_base_url": args.base_url,
        "generated_from": [f.relative_to(root).as_posix() for f in files],
        "routes": routes,
    }
    Path(root / args.out).write_text(
        json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Da ghi {args.out}: {len(routes)} route tu {len(files)} controller")
    for r in routes:
        print(f"  {r['url_path']:<26} dong {r['line_start']:>3}-{r['line_end']:<3} params={r['params']}")


if __name__ == "__main__":
    main()
