// Plain value types shared by every module. No Arduino or ESP-IDF header is included anywhere in this library, so the same
// source compiles for the ESP32 and for the host (native tests, the host emulation, the simulator scenario).
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace doormat {

struct Rgb {
  uint8_t r, g, b;
};

inline bool operator==(const Rgb& a, const Rgb& b) { return a.r == b.r && a.g == b.g && a.b == b.b; }
inline bool operator!=(const Rgb& a, const Rgb& b) { return !(a == b); }

}  // namespace doormat
