// Wiring and defaults for the ESP32 DevKit (30 or 38 pin, ESP32-WROOM-32) board. The same table is in docs/setup-guide.md.
#pragma once

#define DEVICE_PREFIX "mat"

// Pressure sensor: a force sensing resistor (or pressure pad) with a 10 k fixed resistor to GND, read on an ADC1 pin.
#define PIN_PRESSURE 34
// LED border: WS2812B strip, data through a 330 ohm resistor, 5 V supply with a 1000 uF capacitor across it.
#define PIN_LED 5
#define LED_COUNT 48
// OLED SSD1306 128 x 64, I2C.
#define PIN_SDA 21
#define PIN_SCL 22
#define OLED_ADDR 0x3C
// Speaker amplifier MAX98357A on I2S port 1.
#define PIN_SPK_BCLK 26
#define PIN_SPK_LRC 25
#define PIN_SPK_DIN 27
// Microphone INMP441 on I2S port 0 (L/R pin to GND for the left channel).
#define PIN_MIC_SCK 18
#define PIN_MIC_WS 19
#define PIN_MIC_SD 23

#define AUDIO_RATE 16000
#define SPEAKER_AMPLITUDE 9000

// Where the camera board (AI Thinker ESP32-CAM) serves its stream. The control page lets the user type another address.
#define CAMERA_DEFAULT_URL "http://doormat-cam.local/stream"

// Access point used when no Wi-Fi network is configured or reachable.
#define AP_SSID "doormat-setup"
#define AP_PASS "doormat-setup"
#define STA_CONNECT_TIMEOUT_MS 12000

// Optional build time defaults: copy secrets.h.example to secrets.h to set them. secrets.h is ignored by git.
#if __has_include("secrets.h")
#include "secrets.h"
#endif
#ifndef WIFI_SSID
#define WIFI_SSID ""
#endif
#ifndef WIFI_PASS
#define WIFI_PASS ""
#endif
#ifndef MQTT_HOST
#define MQTT_HOST ""  // empty: MQTT stays off
#endif
#ifndef MQTT_PORT
#define MQTT_PORT 1883
#endif
#ifndef MQTT_USER
#define MQTT_USER ""
#endif
#ifndef MQTT_PASS
#define MQTT_PASS ""
#endif
