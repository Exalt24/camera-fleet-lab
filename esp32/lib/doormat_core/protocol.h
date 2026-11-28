// What goes out: JSON for status and events, the microphone level, the MJPEG part header and the 1 bit BMP of the display.
// Every formatter writes into a caller's buffer and returns the length, or 0 when the text would not fit (never a cut off string).
#pragma once
#include "effects.h"
#include "types.h"

namespace doormat {

struct StatusView {
  const char* id;
  bool occupied;
  Mode mode;           // the base mode the user set
  Mode active;         // what the LEDs show right now (greeting while it flashes)
  Rgb color;
  uint8_t brightness;
  const char* message;  // empty when the display shows only the eyes
  uint8_t micLevel;
  uint32_t uptimeMs;
  uint32_t steps;       // steps detected since boot
  uint32_t greetings;
  uint16_t pressure;    // last raw reading
  const char* net;      // "sta", "ap" or "none"
};

size_t jsonEscape(const char* in, char* out, size_t cap);
size_t formatStatus(char* out, size_t cap, const StatusView& v);
size_t formatPresenceEvent(char* out, size_t cap, bool occupied, uint32_t uptimeMs, uint32_t steps);
size_t formatMicEvent(char* out, size_t cap, uint8_t level);
// A handful of LED pixels as hex, enough for the page to draw the border without sending every pixel.
size_t formatFrameEvent(char* out, size_t cap, const Rgb* leds, size_t n, size_t samples);

// Loudness of a block of 16 bit samples on a 0 .. 100 scale: RMS in dB relative to full scale, -60 dB or lower is 0, 0 dB is 100.
uint8_t micLevelFromSamples(const int16_t* samples, size_t n);

size_t mjpegPartHeader(char* out, size_t cap, size_t jpegLen);
extern const char kMjpegBoundary[];

// BMP file for a 1 bit frame buffer in the layout renderEyes writes (white = 1). Returns the file length or 0 when cap is too small.
size_t framebufferToBmp1bpp(const uint8_t* fb, int w, int h, uint8_t* out, size_t cap);

}  // namespace doormat
