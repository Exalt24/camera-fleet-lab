// Wi-Fi (station with an access point fallback), the REST API, the WebSocket stream and MQTT. Every command that arrives, on any
// of them, goes to one handler that the main file provides, which calls doormat::parseCommand.
#pragma once
#include <Arduino.h>

// route: "greet", "led", "message", "status", "wifi" or null when the body carries a "cmd" field.
// Writes a JSON answer into reply and the HTTP status code into *http.
typedef void (*CommandHandler)(const char* route, const char* body, size_t len, char* reply, size_t replyCap, int* http);
// Fills `out` with the display as a BMP file and returns its length, or 0.
typedef size_t (*DisplayBmpSource)(uint8_t* out, size_t cap);

struct NetHooks {
  CommandHandler handle;
  DisplayBmpSource displayBmp;
};

void netBegin(const char* deviceId, const NetHooks& hooks);
void netLoop();
const char* netMode();                           // "sta", "ap" or "none"
void netBroadcast(const char* json);             // WebSocket text frame to every connected page
void netMqttPublish(const char* subtopic, const char* payload, bool retained);
bool netSaveWifi(const char* ssid, const char* pass);  // stores the credentials and restarts into station mode
