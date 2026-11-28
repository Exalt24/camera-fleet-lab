#include "effects.h"

#include <string.h>

namespace doormat {

namespace {
uint8_t scale(uint8_t v, uint8_t s) { return static_cast<uint8_t>((static_cast<uint16_t>(v) * s + 127) / 255); }
Rgb scaled(Rgb c, uint8_t s) { return Rgb{scale(c.r, s), scale(c.g, s), scale(c.b, s)}; }

// 0..255..0 triangle over a period, no floating point.
uint8_t triangle(uint32_t tMs, uint32_t periodMs) {
  const uint32_t half = periodMs / 2;
  const uint32_t p = tMs % periodMs;
  const uint32_t up = p < half ? p : periodMs - p;
  return static_cast<uint8_t>((up * 255u) / half);
}
}  // namespace

const char* modeName(Mode m) {
  switch (m) {
    case Mode::Off: return "off";
    case Mode::Solid: return "solid";
    case Mode::Breathing: return "breathing";
    case Mode::Chase: return "chase";
    case Mode::Rainbow: return "rainbow";
    case Mode::Greeting: return "greeting";
  }
  return "off";
}

bool modeFromName(const char* name, Mode* out) {
  if (!name || !out) return false;
  static const Mode kSettable[] = {Mode::Off, Mode::Solid, Mode::Breathing, Mode::Chase, Mode::Rainbow};
  for (size_t i = 0; i < sizeof(kSettable) / sizeof(kSettable[0]); i++) {
    if (strcmp(name, modeName(kSettable[i])) == 0) {
      *out = kSettable[i];
      return true;
    }
  }
  return false;
}

Rgb hsvToRgb(uint8_t hue, uint8_t sat, uint8_t val) {
  if (sat == 0) return Rgb{val, val, val};
  const uint8_t region = hue / 43;
  const uint8_t rem = static_cast<uint8_t>((hue - region * 43) * 6);
  const uint8_t p = static_cast<uint8_t>((val * (255 - sat)) >> 8);
  const uint8_t q = static_cast<uint8_t>((val * (255 - ((sat * rem) >> 8))) >> 8);
  const uint8_t t = static_cast<uint8_t>((val * (255 - ((sat * (255 - rem)) >> 8))) >> 8);
  switch (region) {
    case 0: return Rgb{val, t, p};
    case 1: return Rgb{q, val, p};
    case 2: return Rgb{p, val, t};
    case 3: return Rgb{p, q, val};
    case 4: return Rgb{t, p, val};
    default: return Rgb{val, p, q};
  }
}

void renderEffect(Mode mode, Rgb color, uint32_t tMs, Rgb* out, size_t n) {
  if (!out || n == 0) return;
  const Rgb black{0, 0, 0};
  switch (mode) {
    case Mode::Off:
      for (size_t i = 0; i < n; i++) out[i] = black;
      break;
    case Mode::Solid:
      for (size_t i = 0; i < n; i++) out[i] = color;
      break;
    case Mode::Breathing: {
      // 3 s period, never fully dark so the border still reads as "on" at the bottom of the breath.
      const uint8_t level = static_cast<uint8_t>(20 + (static_cast<uint16_t>(triangle(tMs, 3000)) * 235) / 255);
      const Rgb c = scaled(color, level);
      for (size_t i = 0; i < n; i++) out[i] = c;
      break;
    }
    case Mode::Chase: {
      // A bright head with a tail of three dimmer pixels, one step every 60 ms around the border.
      static const uint8_t kTail[4] = {255, 150, 80, 35};
      const size_t head = static_cast<size_t>((tMs / 60) % n);
      for (size_t i = 0; i < n; i++) {
        const size_t d = (head + n - i) % n;
        out[i] = d < 4 ? scaled(color, kTail[d]) : black;
      }
      break;
    }
    case Mode::Rainbow:
      for (size_t i = 0; i < n; i++) {
        const uint8_t hue = static_cast<uint8_t>(((i * 256) / n + tMs / 12) & 255);
        out[i] = hsvToRgb(hue, 255, 255);
      }
      break;
    case Mode::Greeting: {
      // Alternate the chosen colour and white every 250 ms, then fade over the last 500 ms of the greeting.
      const bool even = ((tMs / 250) % 2) == 0;
      Rgb c = even ? color : Rgb{255, 255, 255};
      const uint32_t fadeStart = EffectEngine::kGreetingMs - 500;
      if (tMs >= fadeStart) {
        const uint32_t left = tMs >= EffectEngine::kGreetingMs ? 0 : EffectEngine::kGreetingMs - tMs;
        c = scaled(c, static_cast<uint8_t>((left * 255) / 500));
      }
      for (size_t i = 0; i < n; i++) out[i] = c;
      break;
    }
  }
}

EffectEngine::EffectEngine()
    : mode_(Mode::Breathing), color_{0, 160, 255}, brightness_(160), greeting_(false), greetingStart_(0) {}

void EffectEngine::setMode(Mode m) {
  // Greeting is transient: it can only be started by triggerGreeting.
  if (m != Mode::Greeting) mode_ = m;
}

void EffectEngine::triggerGreeting(uint32_t nowMs) {
  greeting_ = true;
  greetingStart_ = nowMs;
}

bool EffectEngine::greetingActive(uint32_t nowMs) const {
  return greeting_ && static_cast<uint32_t>(nowMs - greetingStart_) < kGreetingMs;
}

void EffectEngine::render(uint32_t nowMs, Rgb* out, size_t n) const {
  if (!out || n == 0) return;
  if (greetingActive(nowMs)) {
    renderEffect(Mode::Greeting, color_, static_cast<uint32_t>(nowMs - greetingStart_), out, n);
  } else {
    renderEffect(mode_, color_, nowMs, out, n);
  }
  if (brightness_ != 255) {
    for (size_t i = 0; i < n; i++) out[i] = scaled(out[i], brightness_);
  }
}

}  // namespace doormat
