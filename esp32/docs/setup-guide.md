# Setup guide for the person who flashes the board

This is for a technician with the parts on a bench. It covers the wiring, building and flashing the two boards, getting a phone connected, and what to check when something is off. **The firmware was written and tested in simulators and on the host and has never been flashed to a real board, so treat the wiring table and the thresholds as a first draft to confirm with a meter and the serial monitor.** The limits are listed in [`../README.md`](../README.md#limits).

## Parts

| Part | Used for | Notes |
|---|---|---|
| ESP32 DevKit (ESP32-WROOM-32, 30 or 38 pin) | the doormat board | the build target is `esp32dev` |
| AI Thinker ESP32-CAM with an OV2640 | the camera | a separate board, build target `esp32cam`; flash it with a USB serial adapter (3.3 V logic) |
| Pressure pad or force sensing resistor | presence | any pad whose resistance falls when stepped on; a 10 k resistor to ground makes the divider |
| WS2812B strip, 48 pixels | the LED border | 5 V; `LED_COUNT` in `firmware/config.h` |
| SSD1306 OLED 128 x 64, I2C | the eyes and messages | address 0x3C |
| MAX98357A I2S amplifier and a small speaker | the greeting sound | 4 to 8 ohm, 3 W |
| INMP441 I2S microphone | the level meter | L/R pin to ground |
| 5 V supply, 3 A or more | LED strip and boards | 48 pixels at full white draw about 2.9 A; the default brightness is 160 of 255 |
| 1000 uF capacitor, 330 ohm resistor | the LED strip | capacitor across the strip supply, resistor in series with the data line |

## Wiring (doormat board)

All pin numbers are GPIO numbers and are set in [`../firmware/config.h`](../firmware/config.h).

| Function | Part pin | ESP32 pin |
|---|---|---|
| Pressure divider middle point | pad and 10 k junction | GPIO 34 (input only, ADC1) |
| LED strip data | DIN, through 330 ohm | GPIO 5 |
| OLED SDA | SDA | GPIO 21 |
| OLED SCL | SCL | GPIO 22 |
| Speaker amplifier bit clock | BCLK | GPIO 26 |
| Speaker amplifier word select | LRC | GPIO 25 |
| Speaker amplifier data | DIN | GPIO 27 |
| Microphone bit clock | SCK | GPIO 18 |
| Microphone word select | WS | GPIO 19 |
| Microphone data | SD | GPIO 23 |
| Power | 3.3 V to OLED, amplifier logic and microphone; 5 V to the strip and the amplifier | 3V3, 5V, GND |

Join every ground. The WS2812B data input expects about 4 V for a high; most strips work from the ESP32's 3.3 V on a short wire, and a 74AHCT125 level shifter is the fix when the first pixels flicker.

The camera board is wired by itself: 5 V and ground only. Its pins are fixed by the board.

## Install the tools

```
pip install platformio
git clone https://github.com/Exalt24/camera-fleet-lab
cd camera-fleet-lab/esp32
```

The first build downloads the ESP32 toolchain and the libraries listed in `platformio.ini`, which takes a few minutes.

## Optional: bake in Wi-Fi and MQTT settings

Copy `firmware/secrets.h.example` to `firmware/secrets.h` and fill it in. The file is ignored by git. Skipping this is fine: the board opens its own network on first boot and Wi-Fi can be set from the phone.

## Flash the doormat board

Plug the DevKit in over USB, then:

```
pio run -e esp32dev -t upload
pio device monitor
```

If the upload stalls at "Connecting...", hold the BOOT button on the board until it starts. The serial monitor (115200 baud) should print `[boot] doormat mat-xxxxxx` and either `joined <network>` or `access point doormat-setup up at 192.168.4.1`.

## Connect a phone

1. With no Wi-Fi configured, join the network `doormat-setup` (password `doormat-setup`) on the phone and open `http://192.168.4.1/`.
2. Open **Wi-Fi setup** at the bottom of the page, type the home network name and password and press **Save and restart the board**.
3. The board restarts and joins that network. Open `http://doormat.local/` on the same network. If the phone does not resolve `.local` names, use the address printed by the serial monitor.

The page works the same from either network: the buttons call `/api/...` on the board and a WebSocket on port 81 carries the live presence and microphone events. If the WebSocket cannot connect, the page says `polling` and refreshes every two seconds. The routes and message formats are in [`api.md`](api.md).

Bluetooth: the board advertises as `doormat-mat-xxxxxx`. Writing the same JSON the REST API takes to the command characteristic (UUID in `firmware/ble.cpp`) works for every command, including `{"cmd":"wifi","ssid":"...","pass":"..."}`. There is no pairing, so anyone in radio range can write to it.

## Flash and connect the camera

1. Wire the USB serial adapter to the ESP32-CAM: 5 V, GND, TX to U0R, RX to U0T. Connect GPIO 0 to GND to enter the bootloader, then reset the board.
2. `pio run -e esp32cam -t upload`, then remove the GPIO 0 link and reset again.
3. The camera joins the network set in `secrets.h`, or opens `doormat-cam-setup` (password `doormat-setup`). Its pictures are at `http://doormat-cam.local/capture` and the stream is `http://doormat-cam.local/stream`.
4. On the control page, open **Camera**, type the stream address and press **Show camera**. The address is remembered by the browser.

The camera driver needs a good 5 V supply: a brown-out reboot loop is almost always the supply.

## MQTT

Set `MQTT_HOST`, `MQTT_PORT`, `MQTT_USER` and `MQTT_PASS` in `secrets.h` and flash again. The board then subscribes to `doormat/<id>/cmd/#` and publishes `doormat/<id>/status` (retained) and `doormat/<id>/event/presence`, where `<id>` is the name printed at boot. The topics and an example access list are in [`api.md`](api.md).

## Check and tune

| Check | How | What to expect |
|---|---|---|
| Presence thresholds | open `http://doormat.local/api/status` with nobody on the mat, then with someone standing on it, and read `pressure` | idle well under 900, stepped on well over 1500 (12 bit readings, 0 to 4095); if not, change `onThreshold` and `offThreshold` in `lib/doormat_core/presence.h` and flash again |
| LED count and order | press Solid in the page | the whole border lights; if the colours are swapped, change `NEO_GRB` in `main_device.cpp` |
| Display | stand on the mat | the eyes turn into arches and one of the messages shows under them |
| Sound | stand on the mat | four rising notes; silence means check the amplifier wiring and `SPEAKER_AMPLITUDE` in `config.h` |
| Microphone | clap near the board | the level meter on the page jumps |

## When something is off

| Symptom | Likely cause |
|---|---|
| Page says `offline` | the phone is on another network, or the board is not powered |
| Page says `polling` | port 81 is blocked by the network; the page still works, a little slower |
| Boots, then resets every few seconds | the 5 V supply sags when the strip lights up: use a supply with more current and lower the brightness |
| `OLED not found` in the serial monitor | SDA and SCL swapped, or the display address is 0x3D (`OLED_ADDR`) |
| Greets twice or never | the pad's readings straddle the thresholds; widen the gap between `onThreshold` and `offThreshold` |
| Wi-Fi never joins | the board only does 2.4 GHz; check the password in the page's Wi-Fi setup |
