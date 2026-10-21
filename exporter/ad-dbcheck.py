#!/usr/bin/env python3
"""Esegue `samba-tool dbcheck` e salva l'esito per l'exporter.

Scrive /var/lib/ad-monitoring/dbcheck.json in modo atomico:
  {"timestamp": <unix>, "rc": <int>, "errors": <int>, "lines": <int>, "tail": "<ultime righe>"}
Non modifica la directory: dbcheck senza --fix e' in sola lettura.
"""

import json
import os
import subprocess
import time
from pathlib import Path

STATE = Path("/var/lib/ad-monitoring/dbcheck.json")


def main() -> int:
    started = time.time()
    p = subprocess.run(
        ["samba-tool", "dbcheck", "--cross-ncs", "--quiet"],
        capture_output=True, text=True, timeout=600, check=False,
    )
    output = (p.stdout or "") + (p.stderr or "")
    lines = [ln for ln in output.splitlines() if ln.strip()]
    errors = sum(1 for ln in lines if ln.startswith(("ERROR", "Errore")))
    state = {
        "timestamp": round(time.time(), 3),
        "duration_seconds": round(time.time() - started, 3),
        "rc": p.returncode,
        "errors": errors,
        "lines": len(lines),
        "tail": "\n".join(lines[-20:])[:4000],
    }
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, STATE)
    print(f"dbcheck rc={p.returncode} errors={errors} lines={len(lines)} "
          f"duration={state['duration_seconds']}s")
    return 0 if p.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
