#include "eyes.h"

#include <string.h>

namespace doormat {

EyeAnimator::EyeAnimator(uint32_t seed)
    : seed_(seed ? seed : 1), started_(false), nextBlink_(0), blinkStart_(0), blinking_(false), nextGaze_(0), gx_(0), gy_(0),
      happyUntil_(0), happy_(false) {}

uint32_t EyeAnimator::rnd() {
  seed_ = seed_ * 1664525u + 1013904223u;  // the classic LCG, enough for blink timing
  return seed_ >> 8;
}

void EyeAnimator::setHappy(uint32_t untilMs, uint32_t nowMs) {
  happy_ = true;
  happyUntil_ = untilMs;
  (void)nowMs;
}

EyeFrame EyeAnimator::frame(uint32_t nowMs) {
  if (!started_) {
    started_ = true;
    nextBlink_ = nowMs + 2000 + rnd() % 3000;
    nextGaze_ = nowMs + 1500 + rnd() % 2000;
  }
  if (!blinking_ && static_cast<int32_t>(nowMs - nextBlink_) >= 0) {
    blinking_ = true;
    blinkStart_ = nowMs;
  }
  uint8_t open = 100;
  if (blinking_) {
    const uint32_t e = static_cast<uint32_t>(nowMs - blinkStart_);
    if (e >= kBlinkMs) {
      blinking_ = false;
      nextBlink_ = nowMs + 2000 + rnd() % 3000;
    } else {
      const uint32_t half = kBlinkMs / 2;
      const uint32_t d = e < half ? e : kBlinkMs - e;  // 0 .. half .. 0
      open = static_cast<uint8_t>(100 - (d * 100) / half);
    }
  }
  if (static_cast<int32_t>(nowMs - nextGaze_) >= 0) {
    gx_ = static_cast<int8_t>(static_cast<int>(rnd() % 13) - 6);
    gy_ = static_cast<int8_t>(static_cast<int>(rnd() % 7) - 3);
    nextGaze_ = nowMs + 1500 + rnd() % 2000;
  }
  if (happy_ && static_cast<int32_t>(nowMs - happyUntil_) >= 0) happy_ = false;
  return EyeFrame{open, gx_, gy_, happy_ ? Expression::Happy : Expression::Idle};
}

namespace {
void setPixel(uint8_t* fb, int x, int y, bool on) {
  if (x < 0 || y < 0 || x >= kEyeW || y >= kEyeH) return;
  uint8_t& b = fb[y * (kEyeW / 8) + x / 8];
  const uint8_t m = static_cast<uint8_t>(0x80 >> (x & 7));
  if (on) b |= m; else b &= static_cast<uint8_t>(~m);
}

// Filled ellipse by the integer test (dx/rx)^2 + (dy/ry)^2 <= 1.
void fillEllipse(uint8_t* fb, int cx, int cy, int rx, int ry, bool on) {
  if (rx < 1) rx = 1;
  if (ry < 1) ry = 1;
  for (int y = -ry; y <= ry; y++) {
    for (int x = -rx; x <= rx; x++) {
      if (x * x * ry * ry + y * y * rx * rx <= rx * rx * ry * ry) setPixel(fb, cx + x, cy + y, on);
    }
  }
}
}  // namespace

void renderEyes(const EyeFrame& f, uint8_t* fb) {
  if (!fb) return;
  memset(fb, 0, kEyeBytes);
  const int centres[2] = {34, 94};
  const int cy = kEyeH / 2;
  const int rx = 22;
  const int fullRy = 20;
  int ry = (fullRy * f.open) / 100;
  if (ry < 1) ry = 1;  // a closed eye is a thin line, not nothing
  for (int i = 0; i < 2; i++) {
    const int cx = centres[i];
    fillEllipse(fb, cx, cy, rx, ry, true);
    if (f.expr == Expression::Happy) {
      // Happy eyes: the lower half is cut away and a smaller arc is cut out of what is left, which leaves an upward arch.
      for (int y = cy + 2; y < kEyeH; y++)
        for (int x = cx - rx - 1; x <= cx + rx + 1; x++) setPixel(fb, x, y, false);
      fillEllipse(fb, cx, cy + 9, rx - 7, 12, false);
    } else if (f.open > 30) {
      fillEllipse(fb, cx + f.gazeX, cy + f.gazeY, 8, (8 * f.open) / 100 > 1 ? (8 * f.open) / 100 : 1, false);
    }
  }
}

}  // namespace doormat
