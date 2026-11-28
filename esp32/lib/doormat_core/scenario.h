// A scripted 20 second evening at the door, driven through the real DoormatApp with a seeded noisy pressure signal. It prints a
// trace of what the device does. The host and the ESP32 (under QEMU) run this same code, so their traces can be compared line by line.
#pragma once
#include "app.h"

namespace doormat {

typedef void (*EmitFn)(const char* line, void* ctx);

struct ScenarioSummary {
  uint32_t steps;
  uint32_t greetings;
  uint32_t commandsOk;
  uint32_t commandsRejected;
  uint32_t frameHash;  // FNV-1a over every LED frame and eye frame of the run
};

const size_t kScenarioLeds = 48;

ScenarioSummary runScenario(EmitFn emit, void* ctx);

}  // namespace doormat
