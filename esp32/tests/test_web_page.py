"""The control page, driven in Chromium at a 390 px wide phone viewport against the host emulation. Screenshots land in docs/test-runs/page/.

Each test acts, waits for the page to settle, and then reads what is on screen, as a person would.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
from conftest import SRC

playwright_sync = pytest.importorskip("playwright.sync_api")
pytestmark = pytest.mark.browser

SHOTS = Path(os.environ.get("ESP32_SHOTS") or SRC / "docs" / "test-runs" / "page")


@pytest.fixture(scope="module")
def browser():
    with playwright_sync.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def page(browser, sim):
    ctx = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2, has_touch=True, is_mobile=True)
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.on("dialog", lambda d: (errors.append("dialog: " + d.message), d.dismiss()))
    pg.goto(f"http://127.0.0.1:{sim.http_port}/?wsport={sim.ws_port}")
    pg.wait_for_function("document.getElementById('conn').dataset.state === 'live'", timeout=8000)
    pg.wait_for_timeout(600)
    pg.errors = errors
    yield pg
    assert errors == [], errors
    ctx.close()


def shot(page, name):
    SHOTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(SHOTS / name), full_page=True)


def api(sim, route="status"):
    return httpx.get(f"http://127.0.0.1:{sim.http_port}/api/{route}").json()


def test_the_page_loads_live_and_fits_a_phone(page):
    assert page.inner_text("#conn") == "live"
    assert page.evaluate("document.documentElement.scrollWidth") <= 390, "no sideways scroll at 390 px"
    small = page.evaluate(
        "Array.from(document.querySelectorAll('button')).filter(b => b.offsetParent !== null).map(b => [b.textContent.trim(), b.getBoundingClientRect().height]).filter(x => x[1] < 44)"
    )
    assert small == [], f"tap targets under 44 px: {small}"
    assert page.evaluate("document.querySelector('#eyes').naturalWidth") == 128
    shot(page, "01-loaded-390.png")


def test_greet_button_greets(page, sim):
    before = api(sim)["greetings"]
    page.click("#greet")
    page.wait_for_function("document.getElementById('log').textContent.startsWith('Sent')")
    page.wait_for_timeout(500)
    assert api(sim)["greetings"] == before + 1
    assert page.inner_text("#msg") != "", "the greeting message shows on the display preview"
    shot(page, "02-greeting-390.png")


@pytest.mark.parametrize("mode", ["off", "solid", "breathing", "chase", "rainbow"])
def test_each_led_mode_button_sets_the_mode_and_shows_pressed(page, sim, mode):
    page.click(f"#modes button[data-mode={mode}]")
    page.wait_for_function(f"document.querySelector('#modes button[data-mode={mode}]').getAttribute('aria-pressed') === 'true'", timeout=6000)
    assert api(sim)["mode"] == mode
    others = page.evaluate(f"Array.from(document.querySelectorAll('#modes button')).filter(b => b.dataset.mode !== '{mode}' && b.getAttribute('aria-pressed') === 'true').length")
    assert others == 0


def test_the_border_preview_follows_the_frame_events(page, sim):
    page.click("#modes button[data-mode=solid]")
    page.evaluate("(() => { const c = document.getElementById('color'); c.value = '#ff0000'; c.dispatchEvent(new Event('change')); })()")
    page.evaluate("(() => { const b = document.getElementById('bright'); b.value = 255; b.dispatchEvent(new Event('change')); })()")
    page.wait_for_function("Array.from(document.querySelectorAll('#strip i')).length === 24 && Array.from(document.querySelectorAll('#strip i')).every(i => i.style.background.includes('255, 0, 0'))", timeout=8000)
    assert api(sim)["color"] == "#ff0000"
    page.click("#modes button[data-mode=rainbow]")
    page.wait_for_function("new Set(Array.from(document.querySelectorAll('#strip i')).map(i => i.style.background)).size > 12", timeout=8000)
    shot(page, "03-rainbow-390.png")


def test_brightness_slider_sends_the_value(page, sim):
    page.evaluate("(() => { const b = document.getElementById('bright'); b.value = 42; b.dispatchEvent(new Event('input')); b.dispatchEvent(new Event('change')); })()")
    page.wait_for_function("document.getElementById('brightval').textContent === '42'")
    page.wait_for_timeout(400)
    assert api(sim)["brightness"] == 42


def test_a_typed_message_is_shown_and_html_in_it_stays_text(page, sim):
    text = "<img src=x onerror=alert(1)>"
    page.fill("#msgtext", text)
    page.click("#sendmsg")
    page.wait_for_function("document.getElementById('msg').textContent.length > 0 && document.getElementById('msg').textContent.includes('onerror')", timeout=6000)
    assert page.inner_text("#msg") == text[:32]
    assert page.evaluate("document.querySelectorAll('#msg img').length") == 0
    shot(page, "04-message-390.png")


def test_a_built_in_message_button(page, sim):
    page.click("#presets button:nth-child(2)")
    page.wait_for_timeout(600)
    expected = json.loads(httpx.get(f"http://127.0.0.1:{sim.http_port}/api/messages").text)["messages"][1]
    assert api(sim)["message"] == expected


def test_presence_and_microphone_are_live(page, sim):
    httpx.post(f"http://127.0.0.1:{sim.http_port}/sim/mic", json={"value": 80})
    httpx.post(f"http://127.0.0.1:{sim.http_port}/sim/step", json={"ms": 3000})
    page.wait_for_function("document.getElementById('presence').dataset.state === 'occupied'", timeout=8000)
    assert page.inner_text("#presence-text") == "Someone is on the mat"
    page.wait_for_function("document.getElementById('micval').textContent === '80'", timeout=6000)
    assert page.get_attribute("#meterbox", "aria-valuenow") == "80"
    assert page.evaluate("parseFloat(document.getElementById('mic').style.width)") == 80
    shot(page, "05-occupied-390.png")
    page.wait_for_function("document.getElementById('presence').dataset.state === 'empty'", timeout=10000)
    httpx.post(f"http://127.0.0.1:{sim.http_port}/sim/mic", json={"value": None})


def test_the_display_picture_updates(page):
    first = page.evaluate("document.getElementById('eyes').src")
    page.wait_for_function(f"document.getElementById('eyes').src !== {json.dumps(first)}", timeout=4000)
    assert page.evaluate("document.getElementById('eyes').naturalHeight") == 48


def test_the_camera_view_shows_the_stream(page, sim):
    page.fill("#camurl", f"http://127.0.0.1:{sim.http_port}/stream")
    page.click("#camtoggle")
    page.wait_for_function("document.getElementById('cam').naturalWidth === 320", timeout=8000)
    assert page.inner_text("#camtoggle") == "Hide camera" and page.inner_text("#camnote") == ""
    shot(page, "06-camera-390.png")
    page.click("#camtoggle")
    assert not page.evaluate("document.getElementById('cam').classList.contains('on')")


def test_a_camera_address_that_is_not_http_is_not_loaded(page):
    page.fill("#camurl", "javascript:alert(1)")
    page.click("#camtoggle")
    assert "http://" in page.inner_text("#camnote")
    assert not page.evaluate("document.getElementById('cam').classList.contains('on')")


def test_a_refusal_from_the_board_is_shown_in_words(page):
    page.route("**/api/led", lambda r: r.fulfill(status=400, content_type="application/json", body='{"ok":false,"err":"bad_mode"}'))
    page.click("#modes button[data-mode=chase]")
    page.wait_for_function("document.getElementById('log').className === 'err'")
    assert page.inner_text("#log") == "The board refused it: bad_mode"


def test_an_unreachable_board_is_shown_in_words(page):
    page.route("**/api/greet", lambda r: r.abort())
    page.click("#greet")
    page.wait_for_function("document.getElementById('log').className === 'err'")
    assert page.inner_text("#log") == "Could not reach the board"


def test_the_wifi_form_needs_a_name_and_sends_both_fields(page):
    page.click("details summary")
    page.click("#savewifi")
    assert page.inner_text("#log") == "Type the network name first"
    sent = []
    page.route("**/api/wifi", lambda r: (sent.append(r.request.post_data), r.fulfill(status=200, content_type="application/json", body='{"ok":true,"type":"wifi"}')))
    page.fill("#ssid", "home net")
    page.fill("#pass", "correct horse")
    page.click("#savewifi")
    page.wait_for_function("document.getElementById('log').textContent.startsWith('Saved')")
    assert json.loads(sent[0]) == {"ssid": "home net", "pass": "correct horse"}
    shot(page, "07-wifi-open-390.png")


def test_the_page_falls_back_to_polling_when_the_stream_is_down(browser, sim):
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    pg = ctx.new_page()
    pg.goto(f"http://127.0.0.1:{sim.http_port}/?ws=ws://127.0.0.1:9/")
    pg.wait_for_function("document.getElementById('conn').dataset.state === 'poll'", timeout=8000)
    # The state turns to polling when the stream fails, which can be before the first status answer arrives, so wait for the answer too.
    pg.wait_for_function("document.getElementById('devid').textContent.startsWith('mat-test')", timeout=8000)
    ctx.close()


def test_the_page_says_offline_when_nothing_answers(browser, sim):
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    pg = ctx.new_page()
    pg.route("**/api/status", lambda r: r.abort())
    pg.goto(f"http://127.0.0.1:{sim.http_port}/?ws=ws://127.0.0.1:9/")
    pg.wait_for_function("document.getElementById('conn').dataset.state === 'down'", timeout=8000)
    ctx.close()
