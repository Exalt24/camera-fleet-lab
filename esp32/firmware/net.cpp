#include "net.h"

#include <ESPmDNS.h>
#include <Preferences.h>
#include <PubSubClient.h>
#include <WebServer.h>
#include <WebSocketsServer.h>
#include <WiFi.h>

#include "command.h"
#include "config.h"

extern const uint8_t indexHtmlStart[] asm("_binary_web_index_html_start");

static WebServer server(80);
static WebSocketsServer ws(81);
static WiFiClient mqttNet;
static PubSubClient mqtt(mqttNet);
static NetHooks hooks;
static char deviceId[24];
static const char* mode = "none";
static char mqttCmdPrefix[48];
static uint32_t lastMqttTry = 0;

static void sendJson(int code, const char* body) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(code, "application/json", body);
}

// One handler for POST /api/<route>: the body goes through the same parser as a WebSocket frame or an MQTT payload.
static void restCommand(const char* route) {
  char reply[512];
  int http = 200;
  const String body = server.hasArg("plain") ? server.arg("plain") : String("");
  hooks.handle(route, body.c_str(), body.length(), reply, sizeof(reply), &http);
  sendJson(http, reply);
}

static void startAccessPoint() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  mode = "ap";
  Serial.printf("[net] access point %s up at %s\n", AP_SSID, WiFi.softAPIP().toString().c_str());
}

static void startStation(const char* ssid, const char* pass) {
  WiFi.mode(WIFI_STA);
  WiFi.setHostname("doormat");
  WiFi.begin(ssid, pass);
  const uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < STA_CONNECT_TIMEOUT_MS) delay(200);
  if (WiFi.status() == WL_CONNECTED) {
    mode = "sta";
    Serial.printf("[net] joined %s, address %s\n", ssid, WiFi.localIP().toString().c_str());
  } else {
    Serial.printf("[net] could not join %s in %d ms, falling back to the access point\n", ssid, STA_CONNECT_TIMEOUT_MS);
    startAccessPoint();
  }
}

static void onWsEvent(uint8_t num, WStype_t type, uint8_t* payload, size_t length) {
  if (type != WStype_TEXT) return;
  char reply[512];
  int http = 200;
  hooks.handle(nullptr, reinterpret_cast<const char*>(payload), length, reply, sizeof(reply), &http);
  ws.sendTXT(num, reply);
}

static void onMqtt(char* topic, uint8_t* payload, unsigned int length) {
  const size_t pl = strlen(mqttCmdPrefix);
  if (strncmp(topic, mqttCmdPrefix, pl) != 0) return;
  const char* route = topic + pl;  // doormat/<id>/cmd/<route>
  if (!*route) return;
  char body[doormat::kMaxBody + 1];
  const size_t n = length > doormat::kMaxBody ? doormat::kMaxBody + 1 : length;  // one byte over the limit is enough to be refused
  memcpy(body, payload, n > doormat::kMaxBody ? doormat::kMaxBody : n);
  char reply[512];
  int http = 200;
  hooks.handle(route, body, n, reply, sizeof(reply), &http);
  netMqttPublish("event/ack", reply, false);
}

static void mqttEnsure() {
  if (!MQTT_HOST[0] || mode[0] != 's' || mqtt.connected()) return;
  if (millis() - lastMqttTry < 5000) return;
  lastMqttTry = millis();
  char willTopic[64];
  snprintf(willTopic, sizeof(willTopic), "doormat/%s/status", deviceId);
  const char* will = "{\"t\":\"status\",\"online\":false}";
  const bool ok = mqtt.connect(deviceId, MQTT_USER[0] ? MQTT_USER : nullptr, MQTT_USER[0] ? MQTT_PASS : nullptr, willTopic, 1, true, will);
  if (!ok) {
    Serial.printf("[mqtt] connect failed, state %d\n", mqtt.state());
    return;
  }
  char sub[64];
  snprintf(sub, sizeof(sub), "%s#", mqttCmdPrefix);
  mqtt.subscribe(sub, 1);
  Serial.printf("[mqtt] connected as %s, listening on %s\n", deviceId, sub);
}

void netBegin(const char* id, const NetHooks& h) {
  strncpy(deviceId, id, sizeof(deviceId) - 1);
  hooks = h;
  snprintf(mqttCmdPrefix, sizeof(mqttCmdPrefix), "doormat/%s/cmd/", deviceId);

  Preferences prefs;
  prefs.begin("net", true);
  String ssid = prefs.getString("ssid", WIFI_SSID);
  String pass = prefs.getString("pass", WIFI_PASS);
  prefs.end();
  if (ssid.length() > 0) startStation(ssid.c_str(), pass.c_str());
  else startAccessPoint();

  if (MDNS.begin("doormat")) MDNS.addService("http", "tcp", 80);

  server.on("/", HTTP_GET, []() { server.send_P(200, "text/html", reinterpret_cast<PGM_P>(indexHtmlStart)); });
  server.on("/api/status", HTTP_GET, []() { restCommand("status"); });
  server.on("/api/greet", HTTP_POST, []() { restCommand("greet"); });
  server.on("/api/led", HTTP_POST, []() { restCommand("led"); });
  server.on("/api/message", HTTP_POST, []() { restCommand("message"); });
  server.on("/api/wifi", HTTP_POST, []() { restCommand("wifi"); });
  server.on("/api/display", HTTP_GET, []() {
    static uint8_t bmp[1200];
    const size_t n = hooks.displayBmp ? hooks.displayBmp(bmp, sizeof(bmp)) : 0;
    if (n == 0) {
      sendJson(500, "{\"ok\":false,\"err\":\"display\"}");
      return;
    }
    server.sendHeader("Cache-Control", "no-store");
    server.send_P(200, "image/bmp", reinterpret_cast<const char*>(bmp), n);
  });
  server.onNotFound([]() { sendJson(404, "{\"ok\":false,\"err\":\"not_found\"}"); });
  server.begin();

  ws.begin();
  ws.onEvent(onWsEvent);

  if (MQTT_HOST[0]) {
    mqtt.setServer(MQTT_HOST, MQTT_PORT);
    mqtt.setCallback(onMqtt);
    mqtt.setBufferSize(512);
  }
}

void netLoop() {
  server.handleClient();
  ws.loop();
  if (MQTT_HOST[0]) {
    mqttEnsure();
    mqtt.loop();
  }
}

const char* netMode() { return mode; }

void netBroadcast(const char* json) { ws.broadcastTXT(json); }

void netMqttPublish(const char* subtopic, const char* payload, bool retained) {
  if (!MQTT_HOST[0] || !mqtt.connected()) return;
  char topic[80];
  snprintf(topic, sizeof(topic), "doormat/%s/%s", deviceId, subtopic);
  mqtt.publish(topic, payload, retained);
}

bool netSaveWifi(const char* ssid, const char* pass) {
  Preferences prefs;
  if (!prefs.begin("net", false)) return false;
  prefs.putString("ssid", ssid);
  prefs.putString("pass", pass);
  prefs.end();
  // The reply has to leave before the restart, so the restart is scheduled by the caller after a short delay.
  return true;
}
