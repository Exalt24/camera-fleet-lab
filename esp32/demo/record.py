#!/usr/bin/env python3
# LIFESPAN: permanent (re-records the README hero clip of the control page when the page changes)
"""Records the control page against the host emulation: LED modes, a step on the mat, a message and the camera stand in.

    python esp32/demo/record.py [--out esp32/docs/demo.gif] [--mp4 esp32/docs/demo.mp4]

Playwright records a video of the page at 480 x 760 while this script clicks through a fixed run, and ffmpeg turns it into a GIF with a
single optimised palette. A caption bar names each step and says up front that no board is involved. Needs the compiled core_cli
(`pio run -e core_cli`), Playwright with Chromium and ffmpeg on PATH.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ESP32 = HERE.parent
sys.path.insert(0, str(ESP32 / "host"))

import httpx  # noqa: E402
import sim_server  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

CAPTION_JS = """
(text) => {
  let el = document.getElementById('demo-caption');
  if (!el) {
    el = document.createElement('div');
    el.id = 'demo-caption';
    el.style.cssText = 'position:fixed;left:0;right:0;bottom:0;padding:10px 14px;background:rgba(5,8,11,.92);color:#e8eef4;font:600 15px system-ui,sans-serif;text-align:center;z-index:9999;border-top:1px solid #2a3644';
    document.body.appendChild(el);
  }
  el.textContent = text;
}
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ESP32 / "docs" / "demo.gif"))
    ap.add_argument("--mp4")
    a = ap.parse_args()
    if shutil.which("ffmpeg") is None:
        print("NOT RUN: ffmpeg is not on PATH")
        return 2
    sim = sim_server.Sim("mat-demo")
    sim.start(0, 0)
    work = Path(tempfile.mkdtemp(prefix="doormat-demo-"))
    base = f"http://127.0.0.1:{sim.http_port}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(viewport={"width": 480, "height": 760}, record_video_dir=str(work), record_video_size={"width": 480, "height": 760})
            page = ctx.new_page()
            page.goto(f"{base}/?wsport={sim.ws_port}")
            page.wait_for_function("document.getElementById('conn').dataset.state === 'live'", timeout=8000)

            def cap(text, pause):
                page.evaluate(CAPTION_JS, text)
                page.wait_for_timeout(int(pause * 1000))

            cap("The control page, running against the host emulation (no board)", 2.2)
            page.click("#modes button[data-mode=chase]")
            cap("LED mode: chase", 1.8)
            page.evaluate("(() => { const c = document.getElementById('color'); c.value = '#22cc66'; c.dispatchEvent(new Event('input')); c.dispatchEvent(new Event('change')); })()")
            cap("Colour: green", 1.4)
            page.click("#modes button[data-mode=rainbow]")
            cap("LED mode: rainbow", 1.8)
            httpx.post(f"{base}/sim/mic", json={"value": 62})
            httpx.post(f"{base}/sim/step", json={"ms": 3800})
            cap("Someone steps on the mat: greeting, happy eyes, message", 4.6)
            httpx.post(f"{base}/sim/mic", json={"value": None})
            page.fill("#msgtext", "Mind the step")
            page.click("#sendmsg")
            cap("A message typed on the phone", 2.2)
            page.fill("#camurl", f"{base}/stream")
            page.click("#camtoggle")
            page.evaluate("document.getElementById('cam').scrollIntoView({block: 'center'})")
            cap("Camera view (a generated test frame stands in for the camera board)", 3.0)
            video = page.video
            ctx.close()
            webm = Path(video.path())
            browser.close()
        out = Path(a.out)
        palette = work / "palette.png"
        vf = "fps=10,scale=480:-1:flags=lanczos"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(webm), "-vf", f"{vf},palettegen=max_colors=96", str(palette)], check=True)
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(webm), "-i", str(palette), "-lavfi", f"{vf}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=4", "-loop", "0", str(out)], check=True)
        if a.mp4:
            subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(webm), "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "26", str(a.mp4)], check=True)
        print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KB)")
        return 0
    finally:
        sim.stop()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
