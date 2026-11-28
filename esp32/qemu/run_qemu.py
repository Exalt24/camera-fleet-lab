#!/usr/bin/env python3
# LIFESPAN: permanent (the simulator run of the firmware: build, boot in Espressif's QEMU, compare with the host trace)
"""Boots the real esp32qemu firmware image in Espressif's QEMU and compares what it prints with the host program.

QEMU emulates the Xtensa CPU, flash and UART but not the ADC, I2S, the LED strip peripheral or Wi-Fi, so this firmware build replaces the
pins with a scripted evening (lib/doormat_core/scenario.cpp). The trace it prints must equal, line for line, the trace the same C++ prints
on the host (core_cli scenario). A difference means the code behaves differently on the target CPU.

    pio run -e esp32qemu && pio run -e core_cli     # once
    python qemu/run_qemu.py [--qemu PATH] [--save docs/test-runs/qemu_run.txt]

QEMU is found through --qemu, the QEMU_XTENSA environment variable, PATH, or esp32/.qemu/ (which `--download` fills from Espressif's
GitHub release; the folder is gitignored). Exit 0 only when the traces are identical, 2 when something could not run.
"""
from __future__ import annotations

import argparse
import difflib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE = "esp-develop-9.2.2-20261109"
ASSETS = {
    ("windows", "amd64"): "qemu-xtensa-softmmu-esp_develop_9.2.2_20261109-x86_64-w64-mingw32.tar.xz",
    ("linux", "x86_64"): "qemu-xtensa-softmmu-esp_develop_9.2.2_20261109-x86_64-linux-gnu.tar.xz",
    ("linux", "aarch64"): "qemu-xtensa-softmmu-esp_develop_9.2.2_20261109-aarch64-linux-gnu.tar.xz",
    ("darwin", "arm64"): "qemu-xtensa-softmmu-esp_develop_9.2.2_20261109-aarch64-apple-darwin.tar.xz",
    ("darwin", "x86_64"): "qemu-xtensa-softmmu-esp_develop_9.2.2_20261109-x86_64-apple-darwin.tar.xz",
}
EXE = "qemu-system-xtensa" + (".exe" if os.name == "nt" else "")


def pio_home() -> Path:
    return Path(os.environ.get("PLATFORMIO_CORE_DIR") or Path.home() / ".platformio")


def find_qemu(explicit: str | None) -> Path | None:
    for cand in (explicit, os.environ.get("QEMU_XTENSA")):
        if cand and Path(cand).exists():
            return Path(cand)
    on_path = shutil.which("qemu-system-xtensa")
    if on_path:
        return Path(on_path)
    local = ROOT / ".qemu" / "qemu" / "bin" / EXE
    return local if local.exists() else None


def download_qemu() -> Path:
    key = (platform.system().lower(), platform.machine().lower())
    asset = ASSETS.get(key)
    if not asset:
        raise SystemExit(f"no Espressif QEMU build is listed for {key}")
    dest = ROOT / ".qemu"
    dest.mkdir(exist_ok=True)
    url = f"https://github.com/espressif/qemu/releases/download/{RELEASE}/{asset}"
    print(f"downloading {url}")
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / asset
        urllib.request.urlretrieve(url, archive)
        with tarfile.open(archive) as t:
            t.extractall(dest, filter="data")
    return dest / "qemu" / "bin" / EXE


def merged_flash(build: Path, out: Path) -> None:
    boot_app0 = pio_home() / "packages" / "framework-arduinoespressif32" / "tools" / "partitions" / "boot_app0.bin"
    esptool = pio_home() / "packages" / "tool-esptoolpy" / "esptool.py"
    for need in (build / "bootloader.bin", build / "partitions.bin", build / "firmware.bin", boot_app0, esptool):
        if not need.exists():
            raise SystemExit(f"missing {need}: run `pio run -e esp32qemu` first")
    subprocess.run(
        [sys.executable, str(esptool), "--chip", "esp32", "merge_bin", "--flash_mode", "dio", "--flash_freq", "40m", "--flash_size", "4MB",
         "-o", str(out), "0x1000", str(build / "bootloader.bin"), "0x8000", str(build / "partitions.bin"), "0xe000", str(boot_app0),
         "0x10000", str(build / "firmware.bin")],
        check=True, capture_output=True,
    )
    data = out.read_bytes()
    out.write_bytes(data + b"\xff" * (4 * 1024 * 1024 - len(data)))  # QEMU wants a flash size it knows: 4 MB


def boot(qemu: Path, flash: Path, uart: Path, timeout: float) -> float:
    start = time.time()
    proc = subprocess.Popen(
        [str(qemu), "-nographic", "-machine", "esp32", "-drive", f"file={flash},if=mtd,format=raw", "-serial", f"file:{uart}",
         "-monitor", "none", "-display", "none"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        while time.time() - start < timeout:
            if uart.exists() and "QEMU-RUN-END" in uart.read_text(errors="replace"):
                break
            if proc.poll() is not None:
                break
            time.sleep(0.2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return time.time() - start


def trace_from_uart(text: str) -> list[str]:
    lines = [ln.rstrip("\r") for ln in text.splitlines()]
    if "QEMU-RUN-BEGIN" not in lines or "QEMU-RUN-END" not in lines:
        return []
    return lines[lines.index("QEMU-RUN-BEGIN") + 1 : lines.index("QEMU-RUN-END")]


def host_trace(cli: Path) -> list[str]:
    out = subprocess.run([str(cli)], input="scenario\nquit\n", capture_output=True, text=True, check=True, timeout=60).stdout
    lines = [ln.rstrip("\r") for ln in out.splitlines()]
    return lines[: lines.index("END")]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu")
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--save", help="write the report to this file as well")
    args = ap.parse_args()

    qemu = find_qemu(args.qemu)
    if qemu is None and args.download:
        qemu = download_qemu()
    if qemu is None or not qemu.exists():
        print("NOT RUN: Espressif's qemu-system-xtensa was not found (use --qemu, QEMU_XTENSA, PATH or --download)")
        return 2
    cli = ROOT / ".pio" / "build" / "core_cli" / ("program.exe" if os.name == "nt" else "program")
    if not cli.exists():
        print(f"NOT RUN: {cli} is missing, run `pio run -e core_cli`")
        return 2

    work = Path(tempfile.mkdtemp(prefix="doormat-qemu-"))
    try:
        merged_flash(ROOT / ".pio" / "build" / "esp32qemu", work / "flash.bin")
        uart = work / "uart.txt"
        seconds = boot(qemu, work / "flash.bin", uart, args.timeout)
        text = uart.read_text(errors="replace") if uart.exists() else ""
        target = trace_from_uart(text)
        host = host_trace(cli)
        version = subprocess.run([str(qemu), "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        report = [f"qemu: {version}", f"image: esp32qemu firmware.bin merged with bootloader and partition table, 4 MB flash",
                  f"booted and finished in {seconds:.1f} s", f"target trace lines: {len(target)}   host trace lines: {len(host)}"]
        if not target:
            report.append("NOT RUN: the firmware never printed QEMU-RUN-BEGIN and QEMU-RUN-END, UART text follows")
            report.append(text[-1500:])
            code = 2
        elif target == host:
            report.append("RESULT: IDENTICAL, every line of the target trace equals the host trace")
            report.append(f"last line: {target[-1]}")
            code = 0
        else:
            report.append("RESULT: DIFFERENT")
            report.extend(list(difflib.unified_diff(host, target, "host", "target", lineterm=""))[:40])
            code = 1
        report.append("")
        report.append("--- target trace as printed over the serial port ---")
        report.extend(target)
        out = "\n".join(report)
        print(out)
        if args.save:
            Path(args.save).write_text(out + "\n", encoding="utf-8")
        return code
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
