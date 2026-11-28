#include "protocol.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

namespace doormat {

const char kMjpegBoundary[] = "doormatframe";

size_t jsonEscape(const char* in, char* out, size_t cap) {
  if (!out || cap == 0) return 0;
  size_t n = 0;
  for (const char* p = in ? in : ""; *p; p++) {
    const unsigned char c = static_cast<unsigned char>(*p);
    if (c == '"' || c == '\\') {
      if (n + 2 >= cap) return 0;
      out[n++] = '\\';
      out[n++] = static_cast<char>(c);
    } else if (c < 0x20 || c > 0x7E) {
      continue;  // never emitted: messages are ASCII already, this only protects a caller that skipped the sanitiser
    } else {
      if (n + 1 >= cap) return 0;
      out[n++] = static_cast<char>(c);
    }
  }
  out[n] = '\0';
  return n;
}

namespace {
// snprintf returns what it WOULD have written; anything that does not fit is a failure, not a truncation.
size_t done(int w, size_t cap) { return (w > 0 && static_cast<size_t>(w) < cap) ? static_cast<size_t>(w) : 0; }
}  // namespace

size_t formatStatus(char* out, size_t cap, const StatusView& v) {
  if (!out || cap == 0) return 0;
  char msg[2 * 32 + 2];
  char id[2 * 24 + 2];
  if (jsonEscape(v.message, msg, sizeof(msg)) == 0 && v.message && v.message[0]) return 0;
  if (jsonEscape(v.id, id, sizeof(id)) == 0 && v.id && v.id[0]) return 0;
  if (!v.message || !v.message[0]) msg[0] = '\0';
  if (!v.id || !v.id[0]) id[0] = '\0';
  const int w = snprintf(out, cap,
                         "{\"t\":\"status\",\"id\":\"%s\",\"occupied\":%s,\"mode\":\"%s\",\"active\":\"%s\",\"color\":\"#%02x%02x%02x\","
                         "\"brightness\":%u,\"message\":\"%s\",\"mic\":%u,\"uptime_ms\":%lu,\"steps\":%lu,\"greetings\":%lu,"
                         "\"pressure\":%u,\"net\":\"%s\"}",
                         id, v.occupied ? "true" : "false", modeName(v.mode), modeName(v.active), v.color.r, v.color.g, v.color.b,
                         static_cast<unsigned>(v.brightness), msg, static_cast<unsigned>(v.micLevel),
                         static_cast<unsigned long>(v.uptimeMs), static_cast<unsigned long>(v.steps),
                         static_cast<unsigned long>(v.greetings), static_cast<unsigned>(v.pressure), v.net ? v.net : "none");
  return done(w, cap);
}

size_t formatPresenceEvent(char* out, size_t cap, bool occupied, uint32_t uptimeMs, uint32_t steps) {
  if (!out || cap == 0) return 0;
  const int w = snprintf(out, cap, "{\"t\":\"presence\",\"state\":\"%s\",\"uptime_ms\":%lu,\"steps\":%lu}", occupied ? "occupied" : "empty",
                         static_cast<unsigned long>(uptimeMs), static_cast<unsigned long>(steps));
  return done(w, cap);
}

size_t formatMicEvent(char* out, size_t cap, uint8_t level) {
  if (!out || cap == 0) return 0;
  const int w = snprintf(out, cap, "{\"t\":\"mic\",\"level\":%u}", static_cast<unsigned>(level));
  return done(w, cap);
}

size_t formatFrameEvent(char* out, size_t cap, const Rgb* leds, size_t n, size_t samples) {
  if (!out || cap == 0 || !leds || n == 0 || samples == 0) return 0;
  if (samples > n) samples = n;
  size_t pos = 0;
  int w = snprintf(out, cap, "{\"t\":\"frame\",\"n\":%u,\"px\":\"", static_cast<unsigned>(samples));
  if (w <= 0 || static_cast<size_t>(w) >= cap) return 0;
  pos = static_cast<size_t>(w);
  for (size_t i = 0; i < samples; i++) {
    const Rgb& c = leds[(i * n) / samples];
    w = snprintf(out + pos, cap - pos, "%02x%02x%02x", c.r, c.g, c.b);
    if (w <= 0 || pos + static_cast<size_t>(w) >= cap) return 0;
    pos += static_cast<size_t>(w);
  }
  w = snprintf(out + pos, cap - pos, "\"}");
  if (w <= 0 || pos + static_cast<size_t>(w) >= cap) return 0;
  return pos + static_cast<size_t>(w);
}

uint8_t micLevelFromSamples(const int16_t* samples, size_t n) {
  if (!samples || n == 0) return 0;
  double acc = 0;
  for (size_t i = 0; i < n; i++) acc += static_cast<double>(samples[i]) * samples[i];
  const double rms = sqrt(acc / static_cast<double>(n));
  if (rms < 1.0) return 0;
  const double db = 20.0 * log10(rms / 32768.0);  // 0 dB at full scale, negative below
  if (db <= -60.0) return 0;
  if (db >= 0.0) return 100;
  return static_cast<uint8_t>(((db + 60.0) / 60.0) * 100.0 + 0.5);
}

size_t mjpegPartHeader(char* out, size_t cap, size_t jpegLen) {
  if (!out || cap == 0 || jpegLen == 0) return 0;
  const int w = snprintf(out, cap, "\r\n--%s\r\nContent-Type: image/jpeg\r\nContent-Length: %lu\r\n\r\n", kMjpegBoundary,
                         static_cast<unsigned long>(jpegLen));
  return done(w, cap);
}

size_t framebufferToBmp1bpp(const uint8_t* fb, int w, int h, uint8_t* out, size_t cap) {
  if (!fb || !out || w <= 0 || h <= 0 || (w % 8) != 0) return 0;
  const size_t rowIn = static_cast<size_t>(w / 8);
  const size_t rowOut = (rowIn + 3) & ~static_cast<size_t>(3);  // BMP rows are padded to 4 bytes
  const size_t pixels = rowOut * static_cast<size_t>(h);
  const size_t headerLen = 14 + 40 + 8;                          // file header, info header, two palette entries
  const size_t total = headerLen + pixels;
  if (cap < total) return 0;
  memset(out, 0, total);
  auto put32 = [&](size_t at, uint32_t v) {
    out[at] = static_cast<uint8_t>(v);
    out[at + 1] = static_cast<uint8_t>(v >> 8);
    out[at + 2] = static_cast<uint8_t>(v >> 16);
    out[at + 3] = static_cast<uint8_t>(v >> 24);
  };
  out[0] = 'B';
  out[1] = 'M';
  put32(2, static_cast<uint32_t>(total));
  put32(10, static_cast<uint32_t>(headerLen));
  put32(14, 40);
  put32(18, static_cast<uint32_t>(w));
  put32(22, static_cast<uint32_t>(h));  // positive height: rows are stored bottom up
  out[26] = 1;                           // planes
  out[28] = 1;                           // bits per pixel
  put32(34, static_cast<uint32_t>(pixels));
  put32(46, 2);
  // Palette: index 0 black, index 1 a warm white, which is what the OLED looks like.
  out[54] = 0; out[55] = 0; out[56] = 0; out[57] = 0;
  out[58] = 0xE8; out[59] = 0xF4; out[60] = 0xFF; out[61] = 0;
  for (int y = 0; y < h; y++) {
    memcpy(out + headerLen + static_cast<size_t>(h - 1 - y) * rowOut, fb + static_cast<size_t>(y) * rowIn, rowIn);
  }
  return total;
}

}  // namespace doormat
