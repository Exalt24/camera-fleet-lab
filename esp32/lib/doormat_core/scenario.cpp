#include "scenario.h"

#include <stdio.h>
#include <string.h>

namespace doormat {

namespace {

struct Hasher {
  uint32_t h = 2166136261u;
  void add(uint8_t b) {
    h ^= b;
    h *= 16777619u;
  }
};

struct Script {
  uint32_t atMs;
  const char* route;  // null: the body names its own cmd
  const char* body;
};

const Script kScript[] = {
    {3000, nullptr, "{\"cmd\":\"led\",\"mode\":\"chase\",\"color\":\"#ff8800\",\"brightness\":200}"},
    {12500, "led", "{\"mode\":\"rainbow\"}"},
    {13000, "message", "{\"text\":\"Mind the step\"}"},
    {14000, "message", "{\"index\":2}"},
    {15000, nullptr, "{\"cmd\":\"greet\"}"},
    {16000, nullptr, "{\"cmd\":\"led\",\"mode\":\"strobe\"}"},
    {17000, "led", "{\"mode\":\"breathing\",\"color\":\"#22cc66\"}"},
};

// The pressure the sensor would give, before noise.
uint16_t basePressure(uint32_t t) {
  if (t < 1000) return 100;
  if (t < 6000) return 2400;   // someone stands on the mat
  if (t < 6300) return 1200;   // shifting weight: inside the hysteresis band, still occupied
  if (t < 9000) return 100;    // stepped off
  if (t < 9030) return 2400;   // a 30 ms blip, shorter than the debounce
  if (t < 9500) return 100;
  if (t < 12000) return 2400;  // a second visitor
  return 100;
}

const char* eventName(PresenceEvent e) {
  switch (e) {
    case PresenceEvent::StepOn: return "STEP_ON";
    case PresenceEvent::StepOff: return "STEP_OFF";
    case PresenceEvent::None: break;
  }
  return "NONE";
}

}  // namespace

ScenarioSummary runScenario(EmitFn emit, void* ctx) {
  DoormatApp app;
  Hasher hash;
  ScenarioSummary s{0, 0, 0, 0, 0};
  uint32_t seed = 12345;
  auto rnd = [&seed]() {
    seed = seed * 1664525u + 1013904223u;
    return seed >> 16;
  };
  char line[200];
  Rgb leds[kScenarioLeds];
  uint8_t fb[kEyeBytes];
  size_t nextCmd = 0;

  for (uint32_t t = 0; t <= 20000; t += 20) {
    // Noise of +-40 counts on the pressure and a mic that is louder while someone stands there.
    const int noise = static_cast<int>(rnd() % 81) - 40;
    int p = static_cast<int>(basePressure(t)) + noise;
    if (p < 0) p = 0;
    const uint8_t mic = static_cast<uint8_t>(app.occupied() ? 40 + rnd() % 25 : 3 + rnd() % 6);

    while (nextCmd < sizeof(kScript) / sizeof(kScript[0]) && kScript[nextCmd].atMs <= t) {
      const Script& sc = kScript[nextCmd++];
      Command c;
      const ParseError pe = parseCommand(sc.route, sc.body, strlen(sc.body), &c);
      if (pe != ParseError::Ok) {
        s.commandsRejected++;
        snprintf(line, sizeof(line), "[t=%05lu] command rejected: %s", static_cast<unsigned long>(t), errorName(pe));
      } else {
        const ApplyResult ar = app.apply(c, t);
        if (ar == ApplyResult::Ok) s.commandsOk++; else s.commandsRejected++;
        snprintf(line, sizeof(line), "[t=%05lu] command ok: type=%d result=%d", static_cast<unsigned long>(t), static_cast<int>(c.type),
                 static_cast<int>(ar));
      }
      emit(line, ctx);
    }

    const StepResult r = app.step(t, static_cast<uint16_t>(p), mic);
    if (r.event != PresenceEvent::None) {
      snprintf(line, sizeof(line), "[t=%05lu] presence %s raw=%d", static_cast<unsigned long>(t), eventName(r.event), p);
      emit(line, ctx);
    }
    if (r.greeted) {
      snprintf(line, sizeof(line), "[t=%05lu] greeting started, message=\"%s\"", static_cast<unsigned long>(t), app.message(t));
      emit(line, ctx);
    }
    if (app.takeGreeting() && !r.greeted) {
      snprintf(line, sizeof(line), "[t=%05lu] greeting requested, message=\"%s\"", static_cast<unsigned long>(t), app.message(t));
      emit(line, ctx);
    }

    app.renderLeds(t, leds, kScenarioLeds);
    for (size_t i = 0; i < kScenarioLeds; i++) {
      hash.add(leds[i].r);
      hash.add(leds[i].g);
      hash.add(leds[i].b);
    }
    const EyeFrame ef = app.eyes(t);
    renderEyes(ef, fb);
    for (size_t i = 0; i < kEyeBytes; i++) hash.add(fb[i]);

    if (t % 1000 == 0) {
      const char* msg = app.message(t);
      snprintf(line, sizeof(line), "[t=%05lu] mode=%s px0=%02x%02x%02x px7=%02x%02x%02x eyes=%u/%d/%d/%d msg=\"%s\"",
               static_cast<unsigned long>(t), modeName(app.effects().activeMode(t)), leds[0].r, leds[0].g, leds[0].b, leds[7].r,
               leds[7].g, leds[7].b, static_cast<unsigned>(ef.open), static_cast<int>(ef.gazeX), static_cast<int>(ef.gazeY),
               static_cast<int>(ef.expr), msg);
      emit(line, ctx);
    }
  }
  s.steps = app.steps();
  s.greetings = app.greetings();
  s.frameHash = hash.h;
  snprintf(line, sizeof(line), "DONE steps=%lu greetings=%lu commands_ok=%lu commands_rejected=%lu frame_hash=0x%08lx",
           static_cast<unsigned long>(s.steps), static_cast<unsigned long>(s.greetings), static_cast<unsigned long>(s.commandsOk),
           static_cast<unsigned long>(s.commandsRejected), static_cast<unsigned long>(s.frameHash));
  emit(line, ctx);
  return s;
}

}  // namespace doormat
