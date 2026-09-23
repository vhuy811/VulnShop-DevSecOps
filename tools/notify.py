#!/usr/bin/env python3
"""
Gui ket qua pipeline len Telegram.

Doc reports/findings.json roi gui mot tin nhan tom tat. Bien moi truong can:
    TELEGRAM_BOT_TOKEN   token lay tu BotFather
    TELEGRAM_CHAT_ID     id cuoc tro chuyen nhan tin

Cac bien GitHub Actions duoi day la tuy chon, co thi tin nhan day du hon:
    GITHUB_SHA, GITHUB_REF_NAME, GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID

Cach dung:
    python tools/notify.py                     # luon gui
    python tools/notify.py --only-on-confirmed # chi gui khi co lo hong da xac nhan
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests

CONFIRMED = "CONFIRMED"
FILTERED = "FILTERED"
UNCONFIRMED = "UNCONFIRMED"


def build_message(data: dict) -> str:
    s = data.get("summary", {})
    n_conf = s.get(CONFIRMED, 0)
    n_filt = s.get(FILTERED, 0)
    n_unc = s.get(UNCONFIRMED, 0)
    rate = data.get("resolution_rate", 0)

    icon = "\U0001F534" if n_conf else ("\U0001F7E1" if n_unc else "\U0001F7E2")
    ten = os.getenv("GITHUB_REPOSITORY", "").split("/")[-1] or "DevSecOps"
    lines = [f"{icon} <b>{ten} - DevSecOps pipeline</b>"]

    repo = os.getenv("GITHUB_REPOSITORY")
    branch = os.getenv("GITHUB_REF_NAME")
    sha = (os.getenv("GITHUB_SHA") or "")[:7]
    if repo:
        lines.append(f"<code>{repo}</code> | nhanh <b>{branch}</b> | commit <code>{sha}</code>")

    lines += [
        "",
        f"<b>{n_conf}</b> CONFIRMED - da co bang chung khai thac",
        f"<b>{n_filt}</b> FILTERED - loai tru bang bang chung tinh",
        f"<b>{n_unc}</b> UNCONFIRMED - can review tay",
        f"Ti le phan giai tu dong: <b>{rate:.0%}</b>",
    ]

    confirmed = [r for r in data.get("results", []) if r["label"] == CONFIRMED]
    if confirmed:
        lines.append("")
        lines.append("<b>Lo hong da xac nhan:</b>")
        for r in confirmed[:10]:
            lines.append(f"- {r['cwe']} <code>{r['url']}?{r['param']}=</code>")

    unconfirmed = [r for r in data.get("results", []) if r["label"] == UNCONFIRMED]
    if unconfirmed:
        lines.append("")
        lines.append("<b>Can review tay:</b>")
        for r in unconfirmed[:10]:
            lines.append(f"- {r['cwe']} <code>{r['file']}:{r['line']}</code>")

    server = os.getenv("GITHUB_SERVER_URL")
    run_id = os.getenv("GITHUB_RUN_ID")
    if server and repo and run_id:
        lines.append("")
        lines.append(f'<a href="{server}/{repo}/actions/runs/{run_id}">Xem chi tiet lan chay</a>')

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default="reports/findings.json")
    ap.add_argument("--only-on-confirmed", action="store_true",
                    help="Chi gui khi co it nhat mot nhan CONFIRMED, tranh lam phien")
    args = ap.parse_args()

    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("Thieu TELEGRAM_BOT_TOKEN hoac TELEGRAM_CHAT_ID, bo qua buoc thong bao.")
        return 0  # khong lam hong pipeline chi vi khong gui duoc tin nhan

    path = Path(args.findings)
    if not path.exists():
        print(f"Khong tim thay {path}, bo qua buoc thong bao.")
        return 0

    data = json.loads(path.read_text(encoding="utf-8"))
    if args.only_on_confirmed and data.get("summary", {}).get(CONFIRMED, 0) == 0:
        print("Khong co nhan CONFIRMED, khong gui thong bao.")
        return 0

    resp = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": build_message(data),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        },
        timeout=20,
    )
    if resp.status_code != 200:
        print(f"Telegram tra ve {resp.status_code}: {resp.text[:300]}")
        return 0  # van khong lam hong pipeline
    print("Da gui thong bao Telegram.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
