// Presence from one pressure reading: a hysteresis band plus a debounce timer on each edge.
#pragma once
#include "types.h"

namespace doormat {

struct PresenceConfig {
  uint16_t onThreshold = 1500;   // raw 12 bit ADC value that counts as "pressed"
  uint16_t offThreshold = 900;   // must fall to this or below to count as "released"
  uint32_t debounceOnMs = 60;    // the pressed reading must hold this long before a step is reported
  uint32_t debounceOffMs = 400;  // the released reading must hold this long before the mat is called empty
};

enum class PresenceEvent : uint8_t { None, StepOn, StepOff };

class PresenceDetector {
 public:
  explicit PresenceDetector(PresenceConfig cfg = PresenceConfig());
  PresenceEvent update(uint16_t raw, uint32_t nowMs);
  bool occupied() const { return occupied_; }
  uint16_t lastRaw() const { return lastRaw_; }
  const PresenceConfig& config() const { return cfg_; }

 private:
  PresenceConfig cfg_;
  bool occupied_;
  bool pending_;
  uint32_t pendingSince_;
  uint16_t lastRaw_;
};

}  // namespace doormat
