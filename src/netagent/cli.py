"""Command-line interface.

Commands:
  serve         Start the local API + background monitor (default).
  ingest-once   One incremental Suricata ingest pass, then exit.
  investigate   Run one autonomous investigation and print the Persian report.
  discover      One authorized host-discovery pass (nmap -sn / arp-scan).
  fingerprint   Fingerprint one authorized host (OS/services/MAC/PTR).
  version       Print version.
"""

from __future__ import annotations

import argparse
import json
import sys

import uvicorn

from netagent import __version__
from netagent.config import load_settings
from netagent.database import Database
from netagent.services.monitoring import Monitor


def _cmd_serve(args: argparse.Namespace) -> int:
    settings = load_settings()
    # Defensive: refuse to bind publicly unless explicitly configured.
    if args.host:
        settings.app_host = args.host
    if args.port:
        settings.app_port = args.port
    if settings.app_host not in ("127.0.0.1", "localhost"):
        print(
            f"هشدار: اتصال به {settings.app_host} داشبورد/API را در شبکه منتشر "
            "می‌کند؛ این کار توصیه نمی‌شود.",
            file=sys.stderr,
        )
    uvicorn.run(
        "netagent.main:app",
        host=settings.app_host,
        port=settings.app_port,
        log_level="info",
    )
    return 0


def _cmd_ingest_once(args: argparse.Namespace) -> int:
    settings = load_settings()
    db = Database(settings.database_path)
    monitor = Monitor(db, settings)
    try:
        result = monitor.poll_once()
    finally:
        monitor.tailer.close()
        db.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


def _cmd_investigate(args: argparse.Namespace) -> int:
    from netagent.agent.llm_client import LLMClient
    from netagent.services.investigations import run_investigation

    settings = load_settings()
    db = Database(settings.database_path)
    llm = LLMClient(settings) if settings.llm_enabled else None
    try:
        record = run_investigation(
            db, settings, llm,
            target_ip=args.target,
            alert_id=args.alert_id,
            question=args.question,
            run_ping=args.ping,
        )
    finally:
        db.close()
    print(record.get("report_text") or "گزارشی تولید نشد.")
    if record.get("status") == "failed":
        print(f"\nخطا: {record.get('error')}", file=sys.stderr)
        return 1
    return 0


def _cmd_discover(args: argparse.Namespace) -> int:
    from netagent.agent.tools import ToolScope, build_registry, execute_tool
    from netagent.collectors.nmap import TargetNotAuthorized, host_discovery

    settings = load_settings()
    db = Database(settings.database_path)
    try:
        if args.tool == "nmap":
            result = host_discovery(settings, args.cidr)
        else:
            result = execute_tool(
                build_registry(settings), db, settings, "arp_scan",
                {"target": args.cidr},
                ToolScope(settings=settings, extra_targets=[]),
            )
    except TargetNotAuthorized as exc:
        db.close()
        print(f"هدف خارج از محدوده‌ی مجاز است: {exc}", file=sys.stderr)
        return 2
    for host in result.get("hosts", []):
        db.upsert_host(host["ip"])
    db.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


def _cmd_fingerprint(args: argparse.Namespace) -> int:
    from netagent.agent.tools import ToolScope
    from netagent.services.fingerprint import fingerprint_host

    settings = load_settings()
    db = Database(settings.database_path)
    try:
        ToolScope(settings=settings, extra_targets=[]).authorize(args.ip)
    except ValueError as exc:
        db.close()
        print(f"هدف خارج از محدوده‌ی مجاز است: {exc}", file=sys.stderr)
        return 2
    try:
        record = fingerprint_host(db, settings, args.ip, save=True)
    finally:
        db.close()
    print(json.dumps(record, ensure_ascii=False, indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netagent",
        description="Autonomous AI Network Monitoring Agent (Suricata + local LLM)",
    )
    parser.add_argument("--host", default=None, help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="port (default 8000)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("serve", help="اجرای API و مانیتور پس‌زمینه")
    sub.add_parser("ingest-once", help="یک دور خواندن افزایشی eve.json")
    sub.add_parser("version", help="نمایش نسخه")

    inv = sub.add_parser("investigate", help="بررسی خودکار چندمرحله‌ای و چاپ گزارش فارسی")
    inv.add_argument("--target", help="IP هدف")
    inv.add_argument("--alert-id", type=int, help="شناسه هشدار برای تمرکز تحلیل")
    inv.add_argument("--question", help="پرسش اختیاری کاربر")
    inv.add_argument("--ping", action="store_true", help="اجازه اجرای ping محدود")

    disc = sub.add_parser("discover", help="کشف میزبان در یک CIDR مجاز")
    disc.add_argument("--cidr", required=True, help="CIDR داخل MONITOR_CIDRS/AUTHORIZED_TARGETS")
    disc.add_argument("--tool", choices=["nmap", "arp_scan"], default="nmap")

    fp = sub.add_parser("fingerprint", help="شناسایی کامل یک میزبان مجاز")
    fp.add_argument("--ip", required=True, help="IP میزبان داخل محدوده‌ی مجاز")

    args = parser.parse_args(argv)
    if args.command in (None, "serve"):
        return _cmd_serve(args)
    if args.command == "ingest-once":
        return _cmd_ingest_once(args)
    if args.command == "investigate":
        if not args.target and args.alert_id is None:
            print("باید --target یا --alert-id بدهید.", file=sys.stderr)
            return 2
        return _cmd_investigate(args)
    if args.command == "discover":
        return _cmd_discover(args)
    if args.command == "fingerprint":
        return _cmd_fingerprint(args)
    if args.command == "version":
        print(__version__)
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
