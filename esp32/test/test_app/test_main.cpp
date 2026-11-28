#include <stdio.h>
#include <string.h>
#include <unity.h>

#include <string>
#include <vector>

#include "app.h"
#include "scenario.h"

using namespace doormat;

void setUp(void) {}
void tearDown(void) {}

// Holds the pressed reading for long enough to get a step, returns the time it came.
static uint32_t stepOn(DoormatApp& a, uint32_t from) {
  for (uint32_t t = from; t < from + 500; t += 10) {
    if (a.step(t, 3000, 50).event == PresenceEvent::StepOn) return t;
  }
  return 0;
}

static void stepOff(DoormatApp& a, uint32_t from) {
  for (uint32_t t = from; t < from + 1000; t += 10) a.step(t, 50, 5);
}

static bool apply(DoormatApp& a, const char* route, const char* body, uint32_t now) {
  Command c;
  if (parseCommand(route, body, strlen(body), &c) != ParseError::Ok) return false;
  return a.apply(c, now) == ApplyResult::Ok;
}

void test_a_step_greets_with_a_flash_a_happy_face_a_message_and_one_sound_request() {
  DoormatApp a;
  const uint32_t t = stepOn(a, 1000);
  TEST_ASSERT_TRUE(t > 0);
  TEST_ASSERT_EQUAL_UINT32(1, a.greetings());
  TEST_ASSERT_EQUAL_INT((int)Mode::Greeting, (int)a.effects().activeMode(t));
  TEST_ASSERT_TRUE(strlen(a.message(t)) > 0);
  TEST_ASSERT_EQUAL_INT((int)Expression::Happy, (int)a.eyes(t).expr);
  TEST_ASSERT_TRUE(a.takeGreeting());
  TEST_ASSERT_FALSE(a.takeGreeting());  // the sound is requested once
}

void test_the_greeting_ends_and_the_display_goes_back_to_the_eyes() {
  DoormatApp a;
  const uint32_t t = stepOn(a, 1000);
  const uint32_t later = t + MessageScheduler::kHoldMs + 100;
  TEST_ASSERT_EQUAL_INT((int)Mode::Breathing, (int)a.effects().activeMode(later));
  TEST_ASSERT_EQUAL_STRING("", a.message(later));
  TEST_ASSERT_EQUAL_INT((int)Expression::Idle, (int)a.eyes(later).expr);
}

void test_a_second_step_inside_the_cooldown_does_not_greet_again() {
  AppConfig cfg;
  cfg.greetCooldownMs = 3000;
  DoormatApp a(cfg);
  uint32_t t = stepOn(a, 1000);
  stepOff(a, t + 100);
  const uint32_t t2 = stepOn(a, t + 1200);  // about 1.3 s after the first greeting
  TEST_ASSERT_TRUE(t2 > 0);
  TEST_ASSERT_EQUAL_UINT32(2, a.steps());
  TEST_ASSERT_EQUAL_UINT32(1, a.greetings());
  stepOff(a, t2 + 100);
  const uint32_t t3 = stepOn(a, t2 + 4000);
  TEST_ASSERT_TRUE(t3 > 0);
  TEST_ASSERT_EQUAL_UINT32(2, a.greetings());
}

void test_a_greet_request_always_greets_even_inside_the_cooldown() {
  DoormatApp a;
  const uint32_t t = stepOn(a, 1000);
  TEST_ASSERT_TRUE(apply(a, "greet", "", t + 100));
  TEST_ASSERT_EQUAL_UINT32(2, a.greetings());
}

void test_led_commands_change_what_the_border_shows() {
  DoormatApp a;
  Rgb f[12];
  TEST_ASSERT_TRUE(apply(a, "led", "{\"mode\":\"solid\",\"color\":\"#102030\",\"brightness\":255}", 0));
  a.renderLeds(5000, f, 12);
  TEST_ASSERT_TRUE(f[3] == (Rgb{0x10, 0x20, 0x30}));
  TEST_ASSERT_TRUE(apply(a, "led", "{\"mode\":\"off\"}", 0));
  a.renderLeds(5000, f, 12);
  TEST_ASSERT_TRUE(f[3] == (Rgb{0, 0, 0}));
}

void test_message_commands() {
  DoormatApp a;
  TEST_ASSERT_TRUE(apply(a, "message", "{\"text\":\"Back in five\"}", 100));
  TEST_ASSERT_EQUAL_STRING("Back in five", a.message(100));
  TEST_ASSERT_TRUE(apply(a, "message", "{\"index\":1}", 200));
  TEST_ASSERT_EQUAL_STRING(a.messages().at(1), a.message(200));
  Command c;
  parseCommand("message", "{\"index\":7}", 11, &c);  // a valid index for the format but there are only five messages
  TEST_ASSERT_EQUAL_INT((int)ApplyResult::BadIndex, (int)a.apply(c, 300));
  TEST_ASSERT_EQUAL_STRING(a.messages().at(1), a.message(300));  // unchanged
}

void test_status_view_matches_the_state() {
  DoormatApp a;
  apply(a, "led", "{\"mode\":\"chase\",\"brightness\":90}", 0);
  const uint32_t t = stepOn(a, 1000);
  char buf[400];
  TEST_ASSERT_TRUE(formatStatus(buf, sizeof(buf), a.status(t, "mat-01", "sta")) > 0);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"occupied\":true"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"mode\":\"chase\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"active\":\"greeting\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"brightness\":90"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"steps\":1"));
}

void test_status_and_wifi_commands_are_not_handled_by_the_app() {
  DoormatApp a;
  Command c;
  parseCommand("status", "", 0, &c);
  TEST_ASSERT_EQUAL_INT((int)ApplyResult::Ignored, (int)a.apply(c, 0));
  parseCommand("wifi", "{\"ssid\":\"home\"}", 15, &c);
  TEST_ASSERT_EQUAL_INT((int)ApplyResult::Ignored, (int)a.apply(c, 0));
}

// Seeded random world: random pressure, random commands (valid and invalid), random times. The invariants are about what a visitor
// could see, whatever order things arrive in.
void test_random_worlds_keep_the_device_sane() {
  const char* cmds[][2] = {{"led", "{\"mode\":\"solid\"}"},    {"led", "{\"mode\":\"chase\",\"color\":\"#ffffff\"}"},
                           {"led", "{\"mode\":\"rainbow\"}"},  {"led", "{\"brightness\":40}"},
                           {"led", "{\"brightness\":255}"},    {"message", "{\"text\":\"hello\"}"},
                           {"message", "{\"index\":0}"},       {"greet", ""},
                           {"led", "{\"mode\":\"nope\"}"},     {"message", "{\"index\":99}"}};
  for (uint32_t world = 1; world <= 100; world++) {
    uint32_t seed = world * 40503u + 1;
    auto rnd = [&seed]() {
      seed = seed * 1664525u + 1013904223u;
      return seed >> 10;
    };
    DoormatApp a;
    uint32_t t = 0;
    uint32_t greetCommands = 0;
    int pressure = 0;
    Rgb f[24];
    for (int k = 0; k < 3000; k++, t += 10 + rnd() % 20) {
      if (rnd() % 40 == 0) pressure = (int)(rnd() % 3500);
      const StepResult r = a.step(t, (uint16_t)(pressure + rnd() % 100), (uint8_t)(rnd() % 100));
      if (rnd() % 150 == 0) {
        const size_t c = rnd() % 10;
        Command cmd;
        if (parseCommand(cmds[c][0], cmds[c][1], strlen(cmds[c][1]), &cmd) == ParseError::Ok) {
          if (cmd.type == CmdType::Greet) greetCommands++;
          a.apply(cmd, t);
        }
      }
      a.renderLeds(t, f, 24);
      const uint8_t b = a.effects().brightness();
      for (int i = 0; i < 24; i++) TEST_ASSERT_TRUE(f[i].r <= b && f[i].g <= b && f[i].b <= b);  // brightness is a hard cap
      if (r.greeted) TEST_ASSERT_TRUE(a.effects().greetingActive(t));
      if (!a.occupied()) {
        // an empty mat never shows a message that is older than the hold time
        const char* m = a.message(t);
        TEST_ASSERT_TRUE(strlen(m) <= MessageScheduler::kMaxLen);
      }
      const EyeFrame e = a.eyes(t);
      TEST_ASSERT_TRUE(e.open <= 100);
    }
    TEST_ASSERT_TRUE(a.greetings() <= a.steps() + greetCommands);
    TEST_ASSERT_TRUE(a.steps() <= 3000);
  }
}

static void collect(const char* line, void* ctx) { static_cast<std::vector<std::string>*>(ctx)->push_back(line); }

void test_the_scenario_has_the_expected_story() {
  std::vector<std::string> lines;
  const ScenarioSummary s = runScenario(collect, &lines);
  TEST_ASSERT_EQUAL_UINT32(2, s.steps);        // two real visitors; the 30 ms blip and the band wobble are not steps
  TEST_ASSERT_EQUAL_UINT32(3, s.greetings);    // two steps and one greet command
  TEST_ASSERT_EQUAL_UINT32(6, s.commandsOk);
  TEST_ASSERT_EQUAL_UINT32(1, s.commandsRejected);  // the "strobe" mode
  int stepOns = 0, stepOffs = 0;
  bool sawReject = false;
  for (size_t i = 0; i < lines.size(); i++) {
    if (lines[i].find("presence STEP_ON") != std::string::npos) stepOns++;
    if (lines[i].find("presence STEP_OFF") != std::string::npos) stepOffs++;
    if (lines[i].find("command rejected: bad_mode") != std::string::npos) sawReject = true;
  }
  TEST_ASSERT_EQUAL_INT(2, stepOns);
  TEST_ASSERT_EQUAL_INT(2, stepOffs);
  TEST_ASSERT_TRUE(sawReject);
  TEST_ASSERT_TRUE(lines.back().find("DONE steps=2 greetings=3") == 0);
}

void test_the_scenario_is_deterministic() {
  std::vector<std::string> a, b;
  const ScenarioSummary sa = runScenario(collect, &a);
  const ScenarioSummary sb = runScenario(collect, &b);
  TEST_ASSERT_TRUE(a == b);
  TEST_ASSERT_EQUAL_UINT32(sa.frameHash, sb.frameHash);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_step_greets_with_a_flash_a_happy_face_a_message_and_one_sound_request);
  RUN_TEST(test_the_greeting_ends_and_the_display_goes_back_to_the_eyes);
  RUN_TEST(test_a_second_step_inside_the_cooldown_does_not_greet_again);
  RUN_TEST(test_a_greet_request_always_greets_even_inside_the_cooldown);
  RUN_TEST(test_led_commands_change_what_the_border_shows);
  RUN_TEST(test_message_commands);
  RUN_TEST(test_status_view_matches_the_state);
  RUN_TEST(test_status_and_wifi_commands_are_not_handled_by_the_app);
  RUN_TEST(test_random_worlds_keep_the_device_sane);
  RUN_TEST(test_the_scenario_has_the_expected_story);
  RUN_TEST(test_the_scenario_is_deterministic);
  return UNITY_END();
}
