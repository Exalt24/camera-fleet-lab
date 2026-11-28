#include "presence.h"

namespace doormat {

namespace {
PresenceConfig sanitize(PresenceConfig c) {
  if (c.onThreshold < 2) c.onThreshold = 2;
  // A band that is empty or upside down would make the mat flap on every sample, so the off threshold is forced below the on one.
  if (c.offThreshold >= c.onThreshold) c.offThreshold = static_cast<uint16_t>(c.onThreshold - 1);
  return c;
}
}  // namespace

PresenceDetector::PresenceDetector(PresenceConfig cfg)
    : cfg_(sanitize(cfg)), occupied_(false), pending_(false), pendingSince_(0), lastRaw_(0) {}

PresenceEvent PresenceDetector::update(uint16_t raw, uint32_t nowMs) {
  lastRaw_ = raw;
  const bool wantsFlip = occupied_ ? (raw <= cfg_.offThreshold) : (raw >= cfg_.onThreshold);
  if (!wantsFlip) {
    // Inside the hysteresis band, or back on the current side: any half finished edge is forgotten.
    pending_ = false;
    return PresenceEvent::None;
  }
  if (!pending_) {
    pending_ = true;
    pendingSince_ = nowMs;
  }
  const uint32_t needed = occupied_ ? cfg_.debounceOffMs : cfg_.debounceOnMs;
  // Unsigned subtraction keeps this right when millis() wraps after about 49 days.
  if (static_cast<uint32_t>(nowMs - pendingSince_) < needed) return PresenceEvent::None;
  pending_ = false;
  occupied_ = !occupied_;
  return occupied_ ? PresenceEvent::StepOn : PresenceEvent::StepOff;
}

}  // namespace doormat
