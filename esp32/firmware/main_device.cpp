// The doormat board: reads the pressure pad and the microphone, drives the LED border, the OLED and the speaker, and hands
// everything decision-shaped to doormat::DoormatApp (lib/doormat_core), which the host tests run too.
#include <Adafruit_GFX.h>
#include <Adafruit_NeoPixel.h>
#include <Adafruit_SSD1306.h>
#include <Arduino.h>
#include <Wire.h>
#include <driver/i2s.h>

#include "app.h"
#ifdef DOORMAT_NO_BLE
// Wokwi does not simulate the Bluetooth controller (the chip's btController task trips the watchdog there), so the simulator build leaves BLE out.
static void bleBegin(const char*) {}
static size_t bleTake(char*, size_t) { return 0; }
static void bleSetStatus(const char*) {}
#else
#include "ble.h"
#endif
#include "config.h"
#include "net.h"
#include "tones.h"

using namespace doormat;

static DoormatApp app;
static Adafruit_NeoPixel strip(LED_COUNT, PIN_LED, NEO_GRB + NEO_KHZ800);
static Adafruit_SSD1306 oled(128, 64, &Wire, -1);
static char deviceId[24];
static bool oledOk = false;
static uint32_t restartAt = 0;

// ---- audio out: the greeting as PCM through the I2S amplifier, a chunk per pass of loop() ----
static bool playing = false;
static uint32_t playCursor = 0;

static void audioBegin() {
  i2s_config_t cfg = {};
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_TX);
  cfg.sample_rate = AUDIO_RATE;
  cfg.bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT;
  cfg.channel_format = I2S_CHANNEL_FMT_ONLY_LEFT;
  cfg.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  cfg.intr_alloc_flags = ESP_INTR_FLAG_LEVEL1;
  cfg.dma_buf_count = 6;
  cfg.dma_buf_len = 128;
  cfg.tx_desc_auto_clear = true;
  i2s_driver_install(I2S_NUM_1, &cfg, 0, nullptr);
  i2s_pin_config_t pins = {};
  pins.bck_io_num = PIN_SPK_BCLK;
  pins.ws_io_num = PIN_SPK_LRC;
  pins.data_out_num = PIN_SPK_DIN;
  pins.data_in_num = I2S_PIN_NO_CHANGE;
  i2s_set_pin(I2S_NUM_1, &pins);
}

static void audioPump() {
  if (!playing) return;
  int16_t chunk[128];
  renderGreetingPcm(chunk, 128, playCursor, AUDIO_RATE, SPEAKER_AMPLITUDE);
  size_t written = 0;
  i2s_write(I2S_NUM_1, chunk, sizeof(chunk), &written, 20 / portTICK_PERIOD_MS);
  playCursor += written / sizeof(int16_t);
  if (playCursor >= (uint32_t)AUDIO_RATE * greetingTotalMs() / 1000) {
    playing = false;
    i2s_zero_dma_buffer(I2S_NUM_1);
  }
}

// ---- microphone: INMP441 on I2S port 0, 32 bit slots, the useful 18 bits sit at the top ----
static uint8_t micLevel = 0;
static int16_t micBlock[512];
static size_t micFill = 0;

static void micBegin() {
  i2s_config_t cfg = {};
  cfg.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX);
  cfg.sample_rate = AUDIO_RATE;
  cfg.bits_per_sample = I2S_BITS_PER_SAMPLE_32BIT;
  cfg.channel_format = I2S_CHANNEL_FMT_ONLY_LEFT;
  cfg.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  cfg.intr_alloc_flags = ESP_INTR_FLAG_LEVEL1;
  cfg.dma_buf_count = 4;
  cfg.dma_buf_len = 256;
  i2s_driver_install(I2S_NUM_0, &cfg, 0, nullptr);
  i2s_pin_config_t pins = {};
  pins.bck_io_num = PIN_MIC_SCK;
  pins.ws_io_num = PIN_MIC_WS;
  pins.data_out_num = I2S_PIN_NO_CHANGE;
  pins.data_in_num = PIN_MIC_SD;
  i2s_set_pin(I2S_NUM_0, &pins);
}

static void micPump() {
  int32_t raw[128];
  size_t bytes = 0;
  if (i2s_read(I2S_NUM_0, raw, sizeof(raw), &bytes, 0) != ESP_OK) return;
  for (size_t i = 0; i < bytes / sizeof(int32_t) && micFill < 512; i++) micBlock[micFill++] = (int16_t)(raw[i] >> 14);
  if (micFill >= 512) {
    const uint8_t fresh = micLevelFromSamples(micBlock, micFill);
    micLevel = (uint8_t)((micLevel * 3 + fresh) / 4);  // a little smoothing so the meter does not jitter
    micFill = 0;
  }
}

// ---- display: eyes from the core's frame buffer, the message as one line of text under them ----
static void drawDisplay(uint32_t now) {
  if (!oledOk) return;
  static uint8_t fb[kEyeBytes];
  renderEyes(app.eyes(now), fb);
  oled.clearDisplay();
  oled.drawBitmap(0, 0, fb, kEyeW, kEyeH, SSD1306_WHITE);
  const char* msg = app.message(now);
  if (msg[0]) {
    oled.setTextSize(strlen(msg) <= 10 ? 2 : 1);
    int16_t x1, y1;
    uint16_t w, h;
    oled.getTextBounds(msg, 0, 0, &x1, &y1, &w, &h);
    oled.setCursor((128 - (int)w) / 2, 64 - (int)h - 1);
    oled.setTextColor(SSD1306_WHITE);
    oled.print(msg);
  }
  oled.display();
}

static size_t displayBmp(uint8_t* out, size_t cap) {
  uint8_t fb[kEyeBytes];
  renderEyes(app.eyes(millis()), fb);
  return framebufferToBmp1bpp(fb, kEyeW, kEyeH, out, cap);
}

// ---- commands from every path ----
static void handleCommand(const char* route, const char* body, size_t len, char* reply, size_t cap, int* http) {
  Command c;
  const uint32_t now = millis();
  const ParseError pe = parseCommand(route, body, len, &c);
  if (pe != ParseError::Ok) {
    snprintf(reply, cap, "{\"ok\":false,\"err\":\"%s\"}", errorName(pe));
    *http = 400;
    return;
  }
  if (c.type == CmdType::Status) {
    if (formatStatus(reply, cap, app.status(now, deviceId, netMode())) == 0) snprintf(reply, cap, "{\"ok\":false,\"err\":\"status\"}");
    *http = 200;
    return;
  }
  if (c.type == CmdType::Wifi) {
    if (netSaveWifi(c.ssid, c.pass)) {
      restartAt = now + 1500;  // long enough for this answer to leave
      snprintf(reply, cap, "{\"ok\":true,\"type\":\"wifi\",\"restarting\":true}");
      *http = 200;
    } else {
      snprintf(reply, cap, "{\"ok\":false,\"err\":\"storage\"}");
      *http = 500;
    }
    return;
  }
  const ApplyResult r = app.apply(c, now);
  Serial.printf("[cmd] type=%d result=%d\n", (int)c.type, (int)r);
  if (r == ApplyResult::BadIndex) {
    snprintf(reply, cap, "{\"ok\":false,\"err\":\"bad_index\"}");
    *http = 400;
    return;
  }
  snprintf(reply, cap, "{\"ok\":true}");
  *http = 200;
}

void setup() {
  Serial.begin(115200);
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(deviceId, sizeof(deviceId), DEVICE_PREFIX "-%02x%02x%02x", mac[3], mac[4], mac[5]);
  Serial.printf("[boot] doormat %s\n", deviceId);

  analogReadResolution(12);
  analogSetPinAttenuation(PIN_PRESSURE, ADC_11db);
  strip.begin();
  strip.show();
  Wire.begin(PIN_SDA, PIN_SCL);
  oledOk = oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR);
  if (!oledOk) Serial.println("[boot] OLED not found, continuing without a display");
  audioBegin();
  micBegin();

  NetHooks hooks = {handleCommand, displayBmp};
  netBegin(deviceId, hooks);
  bleBegin(deviceId);
}

void loop() {
  static uint32_t lastSense = 0, lastLed = 0, lastDisplay = 0, lastMicEvent = 0, lastFrameEvent = 0, lastStatus = 0;
  const uint32_t now = millis();

  netLoop();
  char ble[257];
  const size_t bn = bleTake(ble, sizeof(ble));
  if (bn > 0) {
    char reply[512];
    int http = 0;
    handleCommand(nullptr, ble, bn, reply, sizeof(reply), &http);
    bleSetStatus(reply);
  }
  micPump();

  if (now - lastSense >= 10) {
    lastSense = now;
    uint32_t acc = 0;
    for (int i = 0; i < 4; i++) acc += analogRead(PIN_PRESSURE);
    const StepResult r = app.step(now, (uint16_t)(acc / 4), micLevel);
    if (r.event != PresenceEvent::None) {
      Serial.printf("[presence] %s raw=%u steps=%lu\n", r.event == PresenceEvent::StepOn ? "STEP_ON" : "STEP_OFF", (unsigned)(acc / 4),
                    (unsigned long)app.steps());
      char msg[128];
      if (formatPresenceEvent(msg, sizeof(msg), app.occupied(), now, app.steps()) > 0) {
        netBroadcast(msg);
        netMqttPublish("event/presence", msg, false);
      }
    }
  }
  if (app.takeGreeting()) {
    Serial.printf("[greeting] message=\"%s\" led=%s\n", app.message(now), modeName(app.effects().activeMode(now)));
    playing = true;
    playCursor = 0;
  }
  audioPump();

  if (now - lastLed >= 16) {
    lastLed = now;
    static Rgb frame[LED_COUNT];
    app.renderLeds(now, frame, LED_COUNT);
    for (int i = 0; i < LED_COUNT; i++) strip.setPixelColor(i, frame[i].r, frame[i].g, frame[i].b);
    strip.show();
    if (now - lastFrameEvent >= 200) {
      lastFrameEvent = now;
      char msg[256];
      if (formatFrameEvent(msg, sizeof(msg), frame, LED_COUNT, 24) > 0) netBroadcast(msg);
    }
  }
  if (now - lastDisplay >= 60) {
    lastDisplay = now;
    drawDisplay(now);
  }
  if (now - lastMicEvent >= 200) {
    lastMicEvent = now;
    char msg[64];
    if (formatMicEvent(msg, sizeof(msg), micLevel) > 0) netBroadcast(msg);
  }
  if (now - lastStatus >= 5000) {
    lastStatus = now;
    char msg[512];
    if (formatStatus(msg, sizeof(msg), app.status(now, deviceId, netMode())) > 0) {
      netMqttPublish("status", msg, true);
      bleSetStatus(msg);
    }
  }
  if (restartAt && (int32_t)(now - restartAt) >= 0) ESP.restart();
}
