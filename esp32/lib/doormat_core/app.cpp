#include "app.h"

namespace doormat {

DoormatApp::DoormatApp(AppConfig cfg)
    : cfg_(cfg), presence_(cfg.presence), eyes_(cfg.eyeSeed), greetPending_(false), hasGreeted_(false), lastGreet_(0), steps_(0),
      greetings_(0), mic_(0) {}

void DoormatApp::greet(uint32_t nowMs) {
  effects_.triggerGreeting(nowMs);
  messages_.onGreeting(nowMs);
  eyes_.setHappy(nowMs + EffectEngine::kGreetingMs, nowMs);
  greetPending_ = true;
  hasGreeted_ = true;
  lastGreet_ = nowMs;
  greetings_++;
}

StepResult DoormatApp::step(uint32_t nowMs, uint16_t pressure, uint8_t micLevel) {
  mic_ = micLevel;
  StepResult r{presence_.update(pressure, nowMs), false};
  if (r.event == PresenceEvent::StepOn) {
    steps_++;
    if (!hasGreeted_ || static_cast<uint32_t>(nowMs - lastGreet_) >= cfg_.greetCooldownMs) {
      greet(nowMs);
      r.greeted = true;
    }
  }
  messages_.tick(nowMs, presence_.occupied());
  return r;
}

ApplyResult DoormatApp::apply(const Command& c, uint32_t nowMs) {
  switch (c.type) {
    case CmdType::Greet:
      greet(nowMs);  // a request from the page or the broker always greets: the cooldown is for the sensor only
      return ApplyResult::Ok;
    case CmdType::Led:
      if (c.hasMode) effects_.setMode(c.mode);
      if (c.hasColor) effects_.setColor(c.color);
      if (c.hasBrightness) effects_.setBrightness(c.brightness);
      return ApplyResult::Ok;
    case CmdType::Message:
      if (c.hasIndex) return messages_.select(c.index, nowMs) ? ApplyResult::Ok : ApplyResult::BadIndex;
      if (c.hasText) return messages_.showCustom(c.text, nowMs) ? ApplyResult::Ok : ApplyResult::Ignored;
      return ApplyResult::Ignored;
    case CmdType::Status:
    case CmdType::Wifi:  // handled by the network layer, which owns the credentials
    case CmdType::None:
      return ApplyResult::Ignored;
  }
  return ApplyResult::Ignored;
}

bool DoormatApp::takeGreeting() {
  const bool p = greetPending_;
  greetPending_ = false;
  return p;
}

StatusView DoormatApp::status(uint32_t nowMs, const char* id, const char* net) const {
  StatusView v;
  v.id = id;
  v.occupied = presence_.occupied();
  v.mode = effects_.baseMode();
  v.active = effects_.activeMode(nowMs);
  v.color = effects_.color();
  v.brightness = effects_.brightness();
  v.message = messages_.current(nowMs);
  v.micLevel = mic_;
  v.uptimeMs = nowMs;
  v.steps = steps_;
  v.greetings = greetings_;
  v.pressure = presence_.lastRaw();
  v.net = net;
  return v;
}

}  // namespace doormat
