// The animated eyes: blink and gaze timing from a seeded generator, and a rasteriser into a 1 bit frame buffer.
#pragma once
#include "types.h"

namespace doormat {

enum class Expression : uint8_t { Idle, Happy };

struct EyeFrame {
  uint8_t open;  // 0 closed .. 100 fully open
  int8_t gazeX;  // pixels the pupils sit off centre
  int8_t gazeY;
  Expression expr;
};

class EyeAnimator {
 public:
  static const uint32_t kBlinkMs = 160;
  explicit EyeAnimator(uint32_t seed = 1);
  void setHappy(uint32_t untilMs, uint32_t nowMs);
  EyeFrame frame(uint32_t nowMs);

 private:
  uint32_t rnd();
  uint32_t seed_;
  bool started_;
  uint32_t nextBlink_;
  uint32_t blinkStart_;
  bool blinking_;
  uint32_t nextGaze_;
  int8_t gx_, gy_;
  uint32_t happyUntil_;
  bool happy_;
};

// The eye area of the display: 128 x 48 pixels, 1 bit per pixel, rows of 16 bytes, most significant bit first (white = 1).
const int kEyeW = 128;
const int kEyeH = 48;
const size_t kEyeBytes = (kEyeW / 8) * kEyeH;
void renderEyes(const EyeFrame& f, uint8_t* fb);

}  // namespace doormat
