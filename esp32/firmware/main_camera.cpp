// The camera board (AI Thinker ESP32-CAM): serves the OV2640 as an MJPEG stream and single JPEGs. It joins the same Wi-Fi network
// as the doormat board, or opens its own access point. The part header of the stream comes from lib/doormat_core/protocol.cpp, which
// the host tests cover. The camera driver itself needs the real sensor and is not exercised anywhere in this repo.
#include <Arduino.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>
#include <ESPmDNS.h>
#include "esp_camera.h"

#include "protocol.h"

#if __has_include("secrets.h")
#include "secrets.h"
#endif
#ifndef WIFI_SSID
#define WIFI_SSID ""
#endif
#ifndef WIFI_PASS
#define WIFI_PASS ""
#endif

// AI Thinker ESP32-CAM pin map.
#define PWDN_GPIO_NUM 32
#define RESET_GPIO_NUM -1
#define XCLK_GPIO_NUM 0
#define SIOD_GPIO_NUM 26
#define SIOC_GPIO_NUM 27
#define Y9_GPIO_NUM 35
#define Y8_GPIO_NUM 34
#define Y7_GPIO_NUM 39
#define Y6_GPIO_NUM 36
#define Y5_GPIO_NUM 21
#define Y4_GPIO_NUM 19
#define Y3_GPIO_NUM 18
#define Y2_GPIO_NUM 5
#define VSYNC_GPIO_NUM 25
#define HREF_GPIO_NUM 23
#define PCLK_GPIO_NUM 22

static WebServer server(80);

static bool cameraBegin() {
  camera_config_t c = {};
  c.ledc_channel = LEDC_CHANNEL_0;
  c.ledc_timer = LEDC_TIMER_0;
  c.pin_d0 = Y2_GPIO_NUM;
  c.pin_d1 = Y3_GPIO_NUM;
  c.pin_d2 = Y4_GPIO_NUM;
  c.pin_d3 = Y5_GPIO_NUM;
  c.pin_d4 = Y6_GPIO_NUM;
  c.pin_d5 = Y7_GPIO_NUM;
  c.pin_d6 = Y8_GPIO_NUM;
  c.pin_d7 = Y9_GPIO_NUM;
  c.pin_xclk = XCLK_GPIO_NUM;
  c.pin_pclk = PCLK_GPIO_NUM;
  c.pin_vsync = VSYNC_GPIO_NUM;
  c.pin_href = HREF_GPIO_NUM;
  c.pin_sccb_sda = SIOD_GPIO_NUM;
  c.pin_sccb_scl = SIOC_GPIO_NUM;
  c.pin_pwdn = PWDN_GPIO_NUM;
  c.pin_reset = RESET_GPIO_NUM;
  c.xclk_freq_hz = 20000000;
  c.pixel_format = PIXFORMAT_JPEG;
  c.frame_size = FRAMESIZE_VGA;  // 640 x 480 keeps the stream steady over Wi-Fi
  c.jpeg_quality = 14;
  c.fb_count = psramFound() ? 2 : 1;
  c.grab_mode = CAMERA_GRAB_LATEST;
  return esp_camera_init(&c) == ESP_OK;
}

static void handleCapture() {
  camera_fb_t* fb = esp_camera_fb_get();
  if (!fb) {
    server.send(503, "text/plain", "no frame");
    return;
  }
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send_P(200, "image/jpeg", reinterpret_cast<const char*>(fb->buf), fb->len);
  esp_camera_fb_return(fb);
}

static void handleStream() {
  WiFiClient client = server.client();
  char head[160];
  snprintf(head, sizeof(head), "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: multipart/x-mixed-replace; boundary=%s\r\n\r\n",
           doormat::kMjpegBoundary);
  client.print(head);
  while (client.connected()) {
    camera_fb_t* fb = esp_camera_fb_get();
    if (!fb) break;
    const size_t n = doormat::mjpegPartHeader(head, sizeof(head), fb->len);
    if (n == 0) {
      esp_camera_fb_return(fb);
      break;
    }
    client.write(reinterpret_cast<const uint8_t*>(head), n);
    client.write(fb->buf, fb->len);
    esp_camera_fb_return(fb);
    delay(1);  // yields to the Wi-Fi task
  }
}

void setup() {
  Serial.begin(115200);
  if (!cameraBegin()) Serial.println("[cam] the camera did not start, check the ribbon cable and the power supply");

  Preferences prefs;
  prefs.begin("net", true);
  String ssid = prefs.getString("ssid", WIFI_SSID);
  String pass = prefs.getString("pass", WIFI_PASS);
  prefs.end();
  bool joined = false;
  if (ssid.length() > 0) {
    WiFi.mode(WIFI_STA);
    WiFi.setHostname("doormat-cam");
    WiFi.begin(ssid.c_str(), pass.c_str());
    for (int i = 0; i < 60 && WiFi.status() != WL_CONNECTED; i++) delay(200);
    joined = WiFi.status() == WL_CONNECTED;
  }
  if (!joined) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("doormat-cam-setup", "doormat-setup");
    Serial.printf("[cam] access point doormat-cam-setup at %s\n", WiFi.softAPIP().toString().c_str());
  } else {
    Serial.printf("[cam] joined %s at %s\n", ssid.c_str(), WiFi.localIP().toString().c_str());
  }
  if (MDNS.begin("doormat-cam")) MDNS.addService("http", "tcp", 80);
  server.on("/stream", HTTP_GET, handleStream);
  server.on("/capture", HTTP_GET, handleCapture);
  server.begin();
}

void loop() { server.handleClient(); }
