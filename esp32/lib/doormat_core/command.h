// One command format for every way in: a REST body, a WebSocket text frame, an MQTT payload and a BLE write all go through
// parseCommand, so a rule written here holds on every path.
#pragma once
#include "effects.h"
#include "types.h"

namespace doormat {

enum class CmdType : uint8_t { None, Greet, Led, Message, Status, Wifi };

enum class ParseError : uint8_t {
  Ok,
  Empty,
  TooLong,
  NotJson,
  UnknownCmd,
  MissingField,
  BadMode,
  BadColor,
  BadBrightness,
  BadText,
  BadIndex,
  BadWifi,
};

struct Command {
  CmdType type;
  bool hasMode;
  Mode mode;
  bool hasColor;
  Rgb color;
  bool hasBrightness;
  uint8_t brightness;
  bool hasText;
  char text[33];
  bool hasIndex;
  uint8_t index;
  char ssid[33];
  char pass[65];
};

const size_t kMaxBody = 256;

const char* errorName(ParseError e);
// "#rrggbb" or "rrggbb", either case. Nothing else.
bool parseHexColor(const char* s, Rgb* out);
// `route` is the verb a REST path or an MQTT topic already names ("greet", "led", "message", "status", "wifi"), or null when the verb
// is the "cmd" field of the body. A body may be empty only for a route that needs no fields (greet, status).
ParseError parseCommand(const char* route, const char* body, size_t len, Command* out);

}  // namespace doormat
