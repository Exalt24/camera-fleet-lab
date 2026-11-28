// The device brain: sensor reading in, commands in, LED frame, eyes, message and "play the greeting" out. Everything the board
// does except talking to pins and radios lives here, so the host runs the same code the ESP32 runs.
#pragma once
#include "command.h"
#include "effects.h"
#include "eyes.h"
#include "messages.h"
#include "presence.h"
#include "protocol.h"

namespace doormat {

struct AppConfig {
  PresenceConfig presence;
  uint32_t eyeSeed = 7;
  uint32_t greetCooldownMs = 3000;  // a step on the mat greets at most once in this window, so a shuffle is not greeted three times
};

struct StepResult {
  PresenceEvent event;
  bool greeted;  // a greeting started during this step
};

enum class ApplyResult : uint8_t { Ok, BadIndex, Ignored };

class DoormatApp {
 public:
  explicit DoormatApp(AppConfig cfg = AppConfig());
  StepResult step(uint32_t nowMs, uint16_t pressure, uint8_t micLevel);
  ApplyResult apply(const Command& c, uint32_t nowMs);
  void renderLeds(uint32_t nowMs, Rgb* out, size_t n) const { effects_.render(nowMs, out, n); }
  EyeFrame eyes(uint32_t nowMs) { return eyes_.frame(nowMs); }
  const char* message(uint32_t nowMs) const { return messages_.current(nowMs); }
  // True once for each greeting that has started since the last call: the board starts the sound when it sees it.
  bool takeGreeting();
  StatusView status(uint32_t nowMs, const char* id, const char* net) const;
  bool occupied() const { return presence_.occupied(); }
  const MessageScheduler& messages() const { return messages_; }
  MessageScheduler& messages() { return messages_; }
  const EffectEngine& effects() const { return effects_; }
  uint32_t steps() const { return steps_; }
  uint32_t greetings() const { return greetings_; }

 private:
  void greet(uint32_t nowMs);
  AppConfig cfg_;
  PresenceDetector presence_;
  EffectEngine effects_;
  MessageScheduler messages_;
  EyeAnimator eyes_;
  bool greetPending_;
  bool hasGreeted_;
  uint32_t lastGreet_;
  uint32_t steps_;
  uint32_t greetings_;
  uint8_t mic_;
};

}  // namespace doormat
