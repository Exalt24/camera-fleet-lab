#!/usr/bin/env python3
# LIFESPAN: permanent (runs the real firmware in the Wokwi simulator when a token is set; never part of CI, which must not need a secret)
"""Runs the esp32wokwi firmware in Wokwi's simulator with wokwi-cli and the scenario in this folder, and saves the log and two pictures.

The diagram has an ESP32 DevKit, a slide potentiometer on GPIO34 standing in for the pressure pad, an SSD1306 OLED and a 16 pixel LED ring.
The scenario moves the slider up (a step), waits for the firmware to print the STEP_ON and greeting lines, moves it down and waits for STEP_OFF.

    pio run -e esp32wokwi
    set WOKWI_CLI_TOKEN=...            (a free token from https://wokwi.com/dashboard/ci, no card needed)
    python wokwi/run_wokwi.py --cli path/to/wokwi-cli [--save docs/test-runs/wokwi_run.txt] [--pictures docs/test-runs]

The token is read from the environment, masked in everything saved, and never written anywhere. Exit code is wokwi-cli's own (0 when the scenario passed).
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(cli: str, extra: list[str], token: str) -> tuple[int, str]:
    p = subprocess.run([cli, str(HERE), "--scenario", "scenario.test.yaml", "--timeout", "60000", *extra], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=240, cwd=HERE, env=dict(os.environ, WOKWI_CLI_TOKEN=token))
    return p.returncode, (p.stdout + p.stderr).replace(token, "***")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", default=shutil.which("wokwi-cli") or "wokwi-cli")
    ap.add_argument("--save")
    ap.add_argument("--pictures", help="folder for the OLED and LED ring pictures (scaled up 4 times)")
    a = ap.parse_args()
    token = os.environ.get("WOKWI_CLI_TOKEN")
    if not token:
        print("NOT RUN: WOKWI_CLI_TOKEN is not set (a free token comes from https://wokwi.com/dashboard/ci)")
        return 2
    if not (HERE.parent / ".pio" / "build" / "esp32wokwi" / "firmware.bin").exists():
        print("NOT RUN: build the firmware first with `pio run -e esp32wokwi`")
        return 2
    code, out = run(a.cli, [], token)
    # The simulator prints the firmware's serial output unbuffered, so a line can be split by the scenario's own log lines. Rejoin for reading.
    print(out)
    if a.save:
        Path(a.save).write_text(out, encoding="utf-8")
    if code == 0 and a.pictures:
        from PIL import Image

        dest = Path(a.pictures)
        dest.mkdir(parents=True, exist_ok=True)
        for part, ms, name in (("oled", 4200, "wokwi_oled.png"), ("ring", 3500, "wokwi_ring.png")):
            raw = dest / ("_raw_" + name)
            c2, o2 = run(a.cli, ["--screenshot-part", part, "--screenshot-time", str(ms), "--screenshot-file", str(raw)], token)
            if c2 == 0 and raw.exists():
                img = Image.open(raw)
                img.resize((img.width * 4, img.height * 4), Image.NEAREST).save(dest / name)
            raw.unlink(missing_ok=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
