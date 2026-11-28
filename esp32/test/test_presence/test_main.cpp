#include <unity.h>

#include "presence.h"

using namespace doormat;

void setUp(void) {}
void tearDown(void) {}

static PresenceConfig cfg() {
  PresenceConfig c;
  c.onThreshold = 1500;
  c.offThreshold = 900;
  c.debounceOnMs = 60;
  c.debounceOffMs = 400;
  return c;
}

void test_starts_empty() {
  PresenceDetector d(cfg());
  TEST_ASSERT_FALSE(d.occupied());
  TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(0, 0));
}

void test_press_shorter_than_debounce_is_not_a_step() {
  PresenceDetector d(cfg());
  for (uint32_t t = 0; t < 50; t += 10) TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(3000, t));
  TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(100, 50));
  TEST_ASSERT_FALSE(d.occupied());
  // The timer restarts: a second short press must not borrow time from the first.
  for (uint32_t t = 60; t < 110; t += 10) TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(3000, t));
  TEST_ASSERT_FALSE(d.occupied());
}

void test_press_held_for_the_debounce_is_exactly_one_step() {
  PresenceDetector d(cfg());
  int steps = 0;
  for (uint32_t t = 0; t <= 500; t += 10) {
    if (d.update(3000, t) == PresenceEvent::StepOn) {
      steps++;
      TEST_ASSERT_EQUAL_UINT32(60, t);
    }
  }
  TEST_ASSERT_EQUAL_INT(1, steps);
  TEST_ASSERT_TRUE(d.occupied());
}

void test_reading_exactly_on_the_threshold_counts() {
  PresenceDetector d(cfg());
  d.update(1500, 0);
  TEST_ASSERT_EQUAL_INT((int)PresenceEvent::StepOn, (int)d.update(1500, 60));
}

void test_reading_just_under_the_threshold_does_not() {
  PresenceDetector d(cfg());
  for (uint32_t t = 0; t < 1000; t += 10) TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(1499, t));
  TEST_ASSERT_FALSE(d.occupied());
}

void test_hysteresis_band_keeps_the_mat_occupied() {
  PresenceDetector d(cfg());
  for (uint32_t t = 0; t <= 100; t += 10) d.update(3000, t);
  TEST_ASSERT_TRUE(d.occupied());
  for (uint32_t t = 110; t < 5000; t += 10) TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(1200, t));
  TEST_ASSERT_TRUE(d.occupied());
}

void test_release_needs_the_off_debounce() {
  PresenceDetector d(cfg());
  for (uint32_t t = 0; t <= 100; t += 10) d.update(3000, t);
  uint32_t offAt = 0;
  for (uint32_t t = 110; t < 1000; t += 10) {
    if (d.update(100, t) == PresenceEvent::StepOff) {
      offAt = t;
      break;
    }
  }
  TEST_ASSERT_EQUAL_UINT32(110 + 400, offAt);
  TEST_ASSERT_FALSE(d.occupied());
}

void test_a_dip_that_returns_to_the_band_cancels_the_release() {
  PresenceDetector d(cfg());
  for (uint32_t t = 0; t <= 100; t += 10) d.update(3000, t);
  for (uint32_t t = 110; t < 400; t += 10) d.update(100, t);  // 290 ms of released
  d.update(1200, 400);                                        // back into the band: the half done release is forgotten
  for (uint32_t t = 410; t < 700; t += 10) TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(100, t));  // 290 ms again
  TEST_ASSERT_TRUE(d.occupied());
}

void test_an_upside_down_band_is_repaired() {
  PresenceConfig c = cfg();
  c.onThreshold = 800;
  c.offThreshold = 2000;
  PresenceDetector d(c);
  TEST_ASSERT_TRUE(d.config().offThreshold < d.config().onThreshold);
  PresenceConfig e = cfg();
  e.onThreshold = 0;
  e.offThreshold = 0;
  PresenceDetector d2(e);
  TEST_ASSERT_TRUE(d2.config().onThreshold >= 2);
  TEST_ASSERT_TRUE(d2.config().offThreshold < d2.config().onThreshold);
}

void test_millis_wraparound_does_not_fire_early_or_late() {
  PresenceDetector d(cfg());
  const uint32_t start = 0xFFFFFFF0u;
  TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(3000, start));
  TEST_ASSERT_EQUAL_INT((int)PresenceEvent::None, (int)d.update(3000, start + 30));  // wraps to 0x0E
  TEST_ASSERT_EQUAL_INT((int)PresenceEvent::StepOn, (int)d.update(3000, start + 60));
}

// A seeded random world: piecewise constant pressure with noise, sampled every 10 ms. The invariants are checked against what the
// detector is allowed to do, not against a second implementation of it.
void test_random_worlds_keep_the_invariants() {
  const PresenceConfig c = cfg();
  for (uint32_t world = 1; world <= 200; world++) {
    uint32_t seed = world * 2654435761u;
    auto rnd = [&seed]() {
      seed = seed * 1664525u + 1013904223u;
      return seed >> 12;
    };
    PresenceDetector d(c);
    bool expectOn = true;     // the next event must be a StepOn
    uint32_t highSince = 0;   // when the current run of "pressed" readings started
    uint32_t lowSince = 0;
    bool inHigh = false, inLow = false;
    int base = 0;
    uint32_t t = 0;
    for (int seg = 0; seg < 40; seg++) {
      base = (int)(rnd() % 3300);
      const int len = 1 + (int)(rnd() % 60);
      for (int k = 0; k < len; k++, t += 10) {
        int v = base + (int)(rnd() % 301) - 150;
        if (v < 0) v = 0;
        if (v > 4095) v = 4095;
        const bool high = v >= c.onThreshold, low = v <= c.offThreshold;
        if (high && !inHigh) highSince = t;
        if (low && !inLow) lowSince = t;
        inHigh = high;
        inLow = low;
        const PresenceEvent e = d.update((uint16_t)v, t);
        if (e == PresenceEvent::StepOn) {
          TEST_ASSERT_TRUE(expectOn);
          TEST_ASSERT_TRUE(high);
          TEST_ASSERT_TRUE(t - highSince >= c.debounceOnMs);
          TEST_ASSERT_TRUE(d.occupied());
          expectOn = false;
        } else if (e == PresenceEvent::StepOff) {
          TEST_ASSERT_FALSE(expectOn);
          TEST_ASSERT_TRUE(low);
          TEST_ASSERT_TRUE(t - lowSince >= c.debounceOffMs);
          TEST_ASSERT_FALSE(d.occupied());
          expectOn = true;
        }
        TEST_ASSERT_EQUAL_INT(expectOn ? 0 : 1, d.occupied() ? 1 : 0);
      }
    }
  }
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_starts_empty);
  RUN_TEST(test_press_shorter_than_debounce_is_not_a_step);
  RUN_TEST(test_press_held_for_the_debounce_is_exactly_one_step);
  RUN_TEST(test_reading_exactly_on_the_threshold_counts);
  RUN_TEST(test_reading_just_under_the_threshold_does_not);
  RUN_TEST(test_hysteresis_band_keeps_the_mat_occupied);
  RUN_TEST(test_release_needs_the_off_debounce);
  RUN_TEST(test_a_dip_that_returns_to_the_band_cancels_the_release);
  RUN_TEST(test_an_upside_down_band_is_repaired);
  RUN_TEST(test_millis_wraparound_does_not_fire_early_or_late);
  RUN_TEST(test_random_worlds_keep_the_invariants);
  return UNITY_END();
}
