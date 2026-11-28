// LED border effects as pure functions of time: the same time always gives the same frame, so a frame can be checked in a test.
#pragma once
#include "types.h"

namespace doormat {

enum class Mode : uint8_t { Off, Solid, Breathing, Chase, Rainbow, Greeting };

const char* modeName(Mode m);
// Accepts the names a user may set: off, solid, breathing, chase, rainbow. "greeting" is a transient flash, never a base mode.
bool modeFromName(const char* name, Mode* out);

void renderEffect(Mode mode, Rgb color, uint32_t tMs, Rgb* out, size_t n);
Rgb hsvToRgb(uint8_t hue, uint8_t sat, uint8_t val);

class EffectEngine {
 public:
  static const uint32_t kGreetingMs = 2500;
  EffectEngine();
  void setMode(Mode m);
  void setColor(Rgb c) { color_ = c; }
  void setBrightness(uint8_t b) { brightness_ = b; }
  void triggerGreeting(uint32_t nowMs);
  bool greetingActive(uint32_t nowMs) const;
  Mode baseMode() const { return mode_; }
  Mode activeMode(uint32_t nowMs) const { return greetingActive(nowMs) ? Mode::Greeting : mode_; }
  Rgb color() const { return color_; }
  uint8_t brightness() const { return brightness_; }
  void render(uint32_t nowMs, Rgb* out, size_t n) const;

 private:
  Mode mode_;
  Rgb color_;
  uint8_t brightness_;
  bool greeting_;
  uint32_t greetingStart_;
};

}  // namespace doormat
