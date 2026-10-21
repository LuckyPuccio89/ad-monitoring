#!/usr/bin/env python3
"""Scrive la sezione [smtp] di /etc/grafana/grafana.ini nel container.

Legge /etc/ad-monitoring/smtp.env (root, 0600), riscrive la sezione [smtp]
preservando il resto del file e lascia a chi chiama il restart di Grafana.
Nessun segreto viene stampato.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ENV_FILE = Path("/etc/ad-monitoring/smtp.env")
CONTAINER = "monitoring-grafana-1"
INI = "/etc/grafana/grafana.ini"


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip()
    return values


def quote_password(pw: str) -> str:
    if any(c in pw for c in "#;") or pw != pw.strip():
        return f'"""{pw}"""'
    return pw


def smtp_block(env: dict[str, str]) -> list[str]:
    return [
        "[smtp]",
        "enabled = true",
        f"host = {env.get('SMTP_HOST', 'localhost:25')}",
        f"user = {env.get('SMTP_USER', '')}",
        f"password = {quote_password(env.get('SMTP_PASSWORD', ''))}",
        f"from_address = {env.get('SMTP_FROM', 'admin@localhost')}",
        f"from_name = {env.get('SMTP_FROM_NAME', 'Grafana')}",
        f"startTLS_policy = {env.get('SMTP_STARTTLS', 'MandatoryStartTLS')}",
        "skip_verify = false",
    ]


def replace_section(ini: str, block: list[str]) -> str:
    lines = ini.splitlines()
    out: list[str] = []
    in_smtp = False
    replaced = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_smtp:
                out.extend(block)
                out.append("")
                replaced = True
                in_smtp = False
            if stripped.lower() == "[smtp]":
                in_smtp = True
                continue
        if in_smtp:
            continue
        out.append(line)
    if in_smtp:
        out.extend(block)
        replaced = True
    if not replaced:
        out.append("")
        out.extend(block)
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    if not ENV_FILE.exists():
        print(f"missing {ENV_FILE}", file=sys.stderr)
        return 1
    env = load_env(ENV_FILE)
    if not env.get("SMTP_PASSWORD"):
        print("SMTP_PASSWORD vuota in smtp.env", file=sys.stderr)
        return 1
    current = subprocess.run(
        ["docker", "exec", CONTAINER, "cat", INI],
        capture_output=True, text=True, check=True,
    ).stdout
    updated = replace_section(current, smtp_block(env))
    subprocess.run(
        ["docker", "exec", "-i", "-u", "root", CONTAINER, "sh", "-c", f"cat > {INI}"],
        input=updated, text=True, check=True,
    )
    subprocess.run(["docker", "exec", "-u", "root", CONTAINER, "chmod", "644", INI], check=True)
    print(f"[smtp] aggiornato in {CONTAINER}:{INI} (host={env.get('SMTP_HOST')}, "
          f"from={env.get('SMTP_FROM')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
