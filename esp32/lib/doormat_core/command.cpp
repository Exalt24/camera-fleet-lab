#include "command.h"

#include <string.h>

#include "messages.h"

namespace doormat {

namespace {

const size_t kMaxPairs = 8;
const size_t kKeyCap = 12;
const size_t kValCap = 66;

struct Pair {
  char key[kKeyCap];
  char sval[kValCap];
  long num;
  bool isStr;
  bool isNum;
  bool isBool;
};

struct Cursor {
  const char* p;
  const char* end;
  void skipWs() {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
  }
};

// Reads a JSON string (the opening quote already consumed) into out. Only \" \\ \/ \n \t escapes are understood; \u is refused so a
// text can never smuggle a control character past the sanitiser.
ParseError readString(Cursor& c, char* out, size_t cap) {
  size_t n = 0;
  while (c.p < c.end) {
    char ch = *c.p++;
    if (ch == '"') {
      out[n] = '\0';
      return ParseError::Ok;
    }
    if (ch == '\\') {
      if (c.p >= c.end) return ParseError::NotJson;
      char e = *c.p++;
      switch (e) {
        case '"': ch = '"'; break;
        case '\\': ch = '\\'; break;
        case '/': ch = '/'; break;
        case 'n': ch = ' '; break;
        case 't': ch = ' '; break;
        default: return ParseError::NotJson;
      }
    }
    if (n + 1 >= cap) return ParseError::TooLong;
    out[n++] = ch;
  }
  return ParseError::NotJson;  // no closing quote
}

ParseError parseObject(const char* body, size_t len, Pair* pairs, size_t* count) {
  *count = 0;
  Cursor c{body, body + len};
  c.skipWs();
  if (c.p >= c.end || *c.p != '{') return ParseError::NotJson;
  c.p++;
  c.skipWs();
  if (c.p < c.end && *c.p == '}') {
    c.p++;
    c.skipWs();
    return c.p == c.end ? ParseError::Ok : ParseError::NotJson;
  }
  for (;;) {
    c.skipWs();
    if (c.p >= c.end || *c.p != '"') return ParseError::NotJson;
    c.p++;
    char key[kKeyCap];
    ParseError e = readString(c, key, sizeof(key));
    if (e == ParseError::TooLong) {
      strcpy(key, "?");  // a key this long is not one of ours: kept as a placeholder and ignored later
      // skip to the closing quote of the key
      while (c.p < c.end && *c.p != '"') c.p++;
      if (c.p >= c.end) return ParseError::NotJson;
      c.p++;
    } else if (e != ParseError::Ok) {
      return e;
    }
    c.skipWs();
    if (c.p >= c.end || *c.p != ':') return ParseError::NotJson;
    c.p++;
    c.skipWs();
    if (c.p >= c.end) return ParseError::NotJson;
    if (*count >= kMaxPairs) return ParseError::TooLong;
    Pair& pr = pairs[*count];
    memset(&pr, 0, sizeof(pr));
    strncpy(pr.key, key, kKeyCap - 1);
    if (*c.p == '"') {
      c.p++;
      e = readString(c, pr.sval, sizeof(pr.sval));
      if (e != ParseError::Ok) return e;
      pr.isStr = true;
    } else if (*c.p == '-' || (*c.p >= '0' && *c.p <= '9')) {
      bool neg = false;
      if (*c.p == '-') {
        neg = true;
        c.p++;
      }
      if (c.p >= c.end || *c.p < '0' || *c.p > '9') return ParseError::NotJson;
      long v = 0;
      while (c.p < c.end && *c.p >= '0' && *c.p <= '9') {
        if (v > 100000) return ParseError::NotJson;  // far beyond any field here, and keeps the loop from overflowing
        v = v * 10 + (*c.p - '0');
        c.p++;
      }
      if (c.p < c.end && (*c.p == '.' || *c.p == 'e' || *c.p == 'E')) return ParseError::NotJson;  // integers only
      pr.num = neg ? -v : v;
      pr.isNum = true;
    } else if (c.end - c.p >= 4 && strncmp(c.p, "true", 4) == 0) {
      c.p += 4;
      pr.isBool = true;
    } else if (c.end - c.p >= 5 && strncmp(c.p, "false", 5) == 0) {
      c.p += 5;
      pr.isBool = true;
    } else {
      return ParseError::NotJson;  // nested objects, arrays and null are not part of the format
    }
    (*count)++;
    c.skipWs();
    if (c.p >= c.end) return ParseError::NotJson;
    if (*c.p == ',') {
      c.p++;
      continue;
    }
    if (*c.p == '}') {
      c.p++;
      c.skipWs();
      return c.p == c.end ? ParseError::Ok : ParseError::NotJson;
    }
    return ParseError::NotJson;
  }
}

const Pair* find(const Pair* pairs, size_t n, const char* key) {
  for (size_t i = 0; i < n; i++)
    if (strcmp(pairs[i].key, key) == 0) return &pairs[i];
  return nullptr;
}

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

const char* errorName(ParseError e) {
  switch (e) {
    case ParseError::Ok: return "ok";
    case ParseError::Empty: return "empty_body";
    case ParseError::TooLong: return "too_long";
    case ParseError::NotJson: return "not_json";
    case ParseError::UnknownCmd: return "unknown_cmd";
    case ParseError::MissingField: return "missing_field";
    case ParseError::BadMode: return "bad_mode";
    case ParseError::BadColor: return "bad_color";
    case ParseError::BadBrightness: return "bad_brightness";
    case ParseError::BadText: return "bad_text";
    case ParseError::BadIndex: return "bad_index";
    case ParseError::BadWifi: return "bad_wifi";
  }
  return "error";
}

bool parseHexColor(const char* s, Rgb* out) {
  if (!s || !out) return false;
  if (*s == '#') s++;
  if (strlen(s) != 6) return false;
  int v[6];
  for (int i = 0; i < 6; i++) {
    v[i] = hexVal(s[i]);
    if (v[i] < 0) return false;
  }
  *out = Rgb{static_cast<uint8_t>(v[0] * 16 + v[1]), static_cast<uint8_t>(v[2] * 16 + v[3]), static_cast<uint8_t>(v[4] * 16 + v[5])};
  return true;
}

ParseError parseCommand(const char* route, const char* body, size_t len, Command* out) {
  if (!out) return ParseError::NotJson;
  memset(out, 0, sizeof(*out));
  if (len > kMaxBody) return ParseError::TooLong;
  if (!body) len = 0;

  Pair pairs[kMaxPairs];
  size_t np = 0;
  bool blank = true;
  for (size_t i = 0; i < len; i++)
    if (body[i] != ' ' && body[i] != '\t' && body[i] != '\r' && body[i] != '\n') blank = false;
  if (!blank) {
    ParseError pe = parseObject(body, len, pairs, &np);
    if (pe != ParseError::Ok) return pe;
  }

  const char* verb = route;
  if (!verb) {
    const Pair* c = find(pairs, np, "cmd");
    if (!c || !c->isStr) return blank ? ParseError::Empty : ParseError::MissingField;
    verb = c->sval;
  }

  if (strcmp(verb, "greet") == 0) {
    out->type = CmdType::Greet;
    return ParseError::Ok;
  }
  if (strcmp(verb, "status") == 0) {
    out->type = CmdType::Status;
    return ParseError::Ok;
  }
  if (strcmp(verb, "led") == 0) {
    const Pair* m = find(pairs, np, "mode");
    const Pair* col = find(pairs, np, "color");
    const Pair* br = find(pairs, np, "brightness");
    if (!m && !col && !br) return ParseError::MissingField;
    if (m) {
      if (!m->isStr || !modeFromName(m->sval, &out->mode)) return ParseError::BadMode;
      out->hasMode = true;
    }
    if (col) {
      if (!col->isStr || !parseHexColor(col->sval, &out->color)) return ParseError::BadColor;
      out->hasColor = true;
    }
    if (br) {
      if (!br->isNum || br->num < 0 || br->num > 255) return ParseError::BadBrightness;
      out->brightness = static_cast<uint8_t>(br->num);
      out->hasBrightness = true;
    }
    out->type = CmdType::Led;
    return ParseError::Ok;
  }
  if (strcmp(verb, "message") == 0) {
    const Pair* t = find(pairs, np, "text");
    const Pair* ix = find(pairs, np, "index");
    if (!t && !ix) return ParseError::MissingField;
    if (t && ix) return ParseError::BadText;  // one or the other, so the intent is never ambiguous
    if (t) {
      if (!t->isStr) return ParseError::BadText;
      if (sanitizeText(t->sval, out->text, sizeof(out->text)) == 0) return ParseError::BadText;
      out->hasText = true;
    } else {
      if (!ix->isNum || ix->num < 0 || ix->num >= static_cast<long>(MessageScheduler::kMaxMessages)) return ParseError::BadIndex;
      out->index = static_cast<uint8_t>(ix->num);
      out->hasIndex = true;
    }
    out->type = CmdType::Message;
    return ParseError::Ok;
  }
  if (strcmp(verb, "wifi") == 0) {
    const Pair* s = find(pairs, np, "ssid");
    const Pair* p = find(pairs, np, "pass");
    if (!s || !s->isStr) return ParseError::MissingField;
    const size_t sl = strlen(s->sval);
    if (sl < 1 || sl > 32) return ParseError::BadWifi;
    size_t pl = 0;
    if (p) {
      if (!p->isStr) return ParseError::BadWifi;
      pl = strlen(p->sval);
      if (pl != 0 && (pl < 8 || pl > 64)) return ParseError::BadWifi;  // WPA2 passphrases are 8 to 63 characters
    }
    strncpy(out->ssid, s->sval, sizeof(out->ssid) - 1);
    if (p) strncpy(out->pass, p->sval, sizeof(out->pass) - 1);
    out->type = CmdType::Wifi;
    return ParseError::Ok;
  }
  return ParseError::UnknownCmd;
}

}  // namespace doormat
