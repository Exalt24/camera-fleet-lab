# Control interfaces

Every way in (REST, WebSocket, MQTT, BLE) ends in one parser, `doormat::parseCommand` in [`lib/doormat_core/command.cpp`](../lib/doormat_core/command.cpp), so a rule written there holds on every path. These routes were exercised against the host emulation ([`host/sim_server.py`](../host/sim_server.py)), which puts the same parser behind an HTTP server, a WebSocket server and an MQTT client. The firmware's own servers (`firmware/net.cpp`) were compiled but not run against a client.

## Commands

A command is a flat JSON object of at most 256 bytes. Numbers are integers, strings may use the escapes `\"`, `\\` and `\/`, and nested objects, arrays and `null` are refused.

| Command | Fields | Effect |
|---|---|---|
| `greet` | none | the greeting: LED flash, happy eyes, a message and the sound; not held back by the sensor cooldown |
| `led` | `mode`: `off`, `solid`, `breathing`, `chase` or `rainbow`; `color`: `#rrggbb`; `brightness`: 0 to 255 | at least one field; unnamed fields stay as they are |
| `message` | `text`: up to 32 printable ASCII characters, or `index`: 0 to 7 | shows the text, or one of the built in messages |
| `status` | none | the status document |
| `wifi` | `ssid`: 1 to 32 characters, `pass`: empty or 8 to 64 characters | stores the credentials and restarts into station mode; never echoed back |

Refusals carry a reason: `empty_body`, `too_long`, `not_json`, `unknown_cmd`, `missing_field`, `bad_mode`, `bad_color`, `bad_brightness`, `bad_text`, `bad_index`, `bad_wifi`. A refused command changes nothing.

## REST (port 80)

| Route | Body | Answer |
|---|---|---|
| `GET /` | | the control page |
| `GET /api/status` | | `{"t":"status","id":"mat-xxxxxx","occupied":false,"mode":"breathing","active":"breathing","color":"#00a0ff","brightness":160,"message":"","mic":4,"uptime_ms":12345,"steps":0,"greetings":0,"pressure":112,"net":"sta"}` |
| `POST /api/greet` | none | `{"ok":true}` |
| `POST /api/led` | `{"mode":"chase","color":"#22cc66","brightness":200}` | `{"ok":true}` or HTTP 400 `{"ok":false,"err":"bad_mode"}` |
| `POST /api/message` | `{"text":"Mind the step"}` or `{"index":2}` | the same |
| `POST /api/wifi` | `{"ssid":"home","pass":"..."}` | `{"ok":true,"type":"wifi","restarting":true}` |
| `GET /api/display` | | the display as a 128 x 48 one bit BMP |

## WebSocket (port 81)

The first frame is the status document. Then:

| Event | Example | Rate |
|---|---|---|
| presence | `{"t":"presence","state":"occupied","uptime_ms":5000,"steps":3}` | on each step on or off |
| mic | `{"t":"mic","level":63}` | five a second; 0 to 100 on a dB scale, see `micLevelFromSamples` |
| frame | `{"t":"frame","n":24,"px":"<24 pixels as rrggbb hex>"}` | five a second |
| status | the status document | after a command that changes it |

Text a client sends is a command with the verb in a `cmd` field, for example `{"cmd":"led","mode":"solid"}`, and the answer comes back on the same socket.

## MQTT

The device id is the client id and the name in the topic. `<id>` is `mat-` and six hex digits on the board.

| Topic | Direction | Payload |
|---|---|---|
| `doormat/<id>/cmd/<verb>` | to the mat | the command body, for example `{"mode":"chase"}` on `.../cmd/led`; `.../cmd/greet` takes an empty payload |
| `doormat/<id>/event/ack` | from the mat | `{"ok":true,"type":"led"}` or `{"ok":false,"err":"bad_mode"}` for every command |
| `doormat/<id>/event/presence` | from the mat | the presence event above |
| `doormat/<id>/status` | from the mat, retained | the status document every 5 seconds; a last will publishes `{"t":"status","online":false}` |

The access list for the repo's mosquitto broker ([`iot/mosquitto/acl.conf`](../../iot/mosquitto/acl.conf)) gives the mat's user `doormat` only its own command topics to read and its own status and event topics to write, and the controller user `doormatctl` the reverse. The tests check that the controller cannot forge a status or an event and that one mat cannot read another's commands.

## BLE

One service, two characteristics: a write only command characteristic that takes the same JSON as REST with a `cmd` field, and a read and notify status characteristic that carries the last answer and the status. The UUIDs are in [`firmware/ble.cpp`](../firmware/ble.cpp). The code compiles into the `esp32dev` firmware. It was not run anywhere: neither QEMU nor Wokwi has a Bluetooth controller.

## Camera board

| Route | Answer |
|---|---|
| `GET /stream` | `multipart/x-mixed-replace; boundary=doormatframe`, one JPEG per part, the part header built by `mjpegPartHeader` |
| `GET /capture` | one JPEG |

The host emulation serves the same two routes from a generated test frame, which is how the framing is tested.
