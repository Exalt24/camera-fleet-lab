#include <string.h>
#include <unity.h>

#include "effects.h"

using namespace doormat;

void setUp(void) {}
void tearDown(void) {}

static const size_t N = 48;
static const Rgb ORANGE{255, 128, 0};

static int nonBlack(const Rgb* f, size_t n) {
  int c = 0;
  for (size_t i = 0; i < n; i++)
    if (f[i].r || f[i].g || f[i].b) c++;
  return c;
}

void test_off_is_black_and_solid_is_the_colour() {
  Rgb f[N];
  renderEffect(Mode::Off, ORANGE, 1234, f, N);
  TEST_ASSERT_EQUAL_INT(0, nonBlack(f, N));
  renderEffect(Mode::Solid, ORANGE, 1234, f, N);
  for (size_t i = 0; i < N; i++) TEST_ASSERT_TRUE(f[i] == ORANGE);
}

void test_breathing_swings_between_a_floor_and_the_full_colour() {
  Rgb f[N];
  uint8_t lo = 255, hi = 0;
  for (uint32_t t = 0; t < 3000; t += 10) {
    renderEffect(Mode::Breathing, ORANGE, t, f, N);
    for (size_t i = 1; i < N; i++) TEST_ASSERT_TRUE(f[i] == f[0]);  // the whole border breathes together
    if (f[0].r < lo) lo = f[0].r;
    if (f[0].r > hi) hi = f[0].r;
  }
  TEST_ASSERT_TRUE(lo >= 18 && lo <= 25);   // floor of about 20 / 255 of the colour, never fully dark
  TEST_ASSERT_TRUE(hi >= 250);
}

void test_breathing_repeats_every_three_seconds() {
  Rgb a[N], b[N];
  renderEffect(Mode::Breathing, ORANGE, 700, a, N);
  renderEffect(Mode::Breathing, ORANGE, 3700, b, N);
  TEST_ASSERT_EQUAL_MEMORY(a, b, sizeof(a));
}

void test_chase_lights_a_head_and_three_tail_pixels_that_move() {
  Rgb f[N];
  renderEffect(Mode::Chase, ORANGE, 0, f, N);
  TEST_ASSERT_EQUAL_INT(4, nonBlack(f, N));
  TEST_ASSERT_TRUE(f[0] == ORANGE);          // head at pixel 0 at t = 0, full colour
  TEST_ASSERT_TRUE(f[1].r == 0);             // nothing ahead of the head
  TEST_ASSERT_TRUE(f[N - 1].r > 0 && f[N - 1].r < ORANGE.r);  // the tail wraps behind it
  renderEffect(Mode::Chase, ORANGE, 60, f, N);
  TEST_ASSERT_TRUE(f[1] == ORANGE);          // one step later the head is at pixel 1
  renderEffect(Mode::Chase, ORANGE, 59, f, N);
  TEST_ASSERT_TRUE(f[0] == ORANGE);          // and not before the 60 ms are up
  renderEffect(Mode::Chase, ORANGE, 60 * N, f, N);
  TEST_ASSERT_TRUE(f[0] == ORANGE);          // a full lap returns to the start
}

void test_chase_works_on_a_strip_shorter_than_its_tail() {
  Rgb f[3];
  renderEffect(Mode::Chase, ORANGE, 0, f, 3);
  TEST_ASSERT_TRUE(f[0] == ORANGE);
  renderEffect(Mode::Chase, ORANGE, 0, f, 1);
  TEST_ASSERT_TRUE(f[0] == ORANGE);
}

void test_rainbow_spreads_the_hues_and_rotates() {
  Rgb a[N], b[N];
  renderEffect(Mode::Rainbow, ORANGE, 0, a, N);
  int different = 0;
  for (size_t i = 1; i < N; i++)
    if (!(a[i] == a[i - 1])) different++;
  TEST_ASSERT_TRUE(different >= (int)N - 2);
  renderEffect(Mode::Rainbow, ORANGE, 600, b, N);
  TEST_ASSERT_TRUE(memcmp(a, b, sizeof(a)) != 0);
  // Full saturation: the weakest channel is exactly 0 on every pixel.
  for (size_t i = 0; i < N; i++) {
    const uint8_t lowest = a[i].r < a[i].g ? (a[i].r < a[i].b ? a[i].r : a[i].b) : (a[i].g < a[i].b ? a[i].g : a[i].b);
    TEST_ASSERT_EQUAL_UINT8(0, lowest);
  }
  // Full value: the strongest channel is 255.
  for (size_t i = 0; i < N; i++) {
    TEST_ASSERT_EQUAL_UINT8(255, a[i].r > a[i].g ? (a[i].r > a[i].b ? a[i].r : a[i].b) : (a[i].g > a[i].b ? a[i].g : a[i].b));
  }
}

void test_hsv_primaries() {
  TEST_ASSERT_TRUE(hsvToRgb(0, 255, 255) == (Rgb{255, 0, 0}));
  Rgb g = hsvToRgb(86, 255, 255);
  TEST_ASSERT_TRUE(g.g == 255 && g.r < 10 && g.b < 10);
  Rgb b = hsvToRgb(171, 255, 255);
  TEST_ASSERT_TRUE(b.b == 255 && b.r < 10 && b.g < 10);
  TEST_ASSERT_TRUE(hsvToRgb(100, 0, 77) == (Rgb{77, 77, 77}));
}

void test_greeting_flashes_between_colour_and_white_then_fades_out() {
  Rgb f[N];
  renderEffect(Mode::Greeting, ORANGE, 0, f, N);
  TEST_ASSERT_TRUE(f[0] == ORANGE);
  renderEffect(Mode::Greeting, ORANGE, 250, f, N);
  TEST_ASSERT_TRUE(f[0] == (Rgb{255, 255, 255}));
  renderEffect(Mode::Greeting, ORANGE, 500, f, N);
  TEST_ASSERT_TRUE(f[0] == ORANGE);
  renderEffect(Mode::Greeting, ORANGE, 1600, f, N);
  TEST_ASSERT_TRUE(f[0] == ORANGE);                // 400 ms before the end the fade has not started
  renderEffect(Mode::Greeting, ORANGE, 1999, f, N);
  TEST_ASSERT_TRUE(f[0] == (Rgb{255, 255, 255}));  // the fade has not started yet
  renderEffect(Mode::Greeting, ORANGE, 2250, f, N);
  TEST_ASSERT_INT_WITHIN(2, 127, f[0].r);          // halfway through the 500 ms fade, white at about half
  renderEffect(Mode::Greeting, ORANGE, EffectEngine::kGreetingMs - 1, f, N);
  TEST_ASSERT_TRUE(f[0].r < 10);
  renderEffect(Mode::Greeting, ORANGE, EffectEngine::kGreetingMs + 100, f, N);
  TEST_ASSERT_EQUAL_INT(0, nonBlack(f, N));
}

void test_the_five_modes_give_five_different_frames() {
  Rgb frames[5][N];
  const Mode modes[5] = {Mode::Solid, Mode::Breathing, Mode::Chase, Mode::Rainbow, Mode::Greeting};
  for (int i = 0; i < 5; i++) renderEffect(modes[i], ORANGE, 1260, frames[i], N);
  for (int i = 0; i < 5; i++)
    for (int j = i + 1; j < 5; j++) TEST_ASSERT_TRUE(memcmp(frames[i], frames[j], sizeof(frames[i])) != 0);
}

void test_the_same_time_always_gives_the_same_frame() {
  Rgb a[N], b[N];
  for (int m = 0; m <= 5; m++) {
    renderEffect((Mode)m, ORANGE, 98765, a, N);
    renderEffect((Mode)m, ORANGE, 98765, b, N);
    TEST_ASSERT_EQUAL_MEMORY(a, b, sizeof(a));
  }
}

void test_null_and_empty_buffers_are_safe() {
  renderEffect(Mode::Chase, ORANGE, 0, nullptr, 10);
  Rgb f[1];
  renderEffect(Mode::Chase, ORANGE, 0, f, 0);
  EffectEngine e;
  e.render(0, nullptr, 5);
  e.render(0, f, 0);
  TEST_PASS();
}

void test_mode_names() {
  Mode m;
  TEST_ASSERT_TRUE(modeFromName("solid", &m) && m == Mode::Solid);
  TEST_ASSERT_TRUE(modeFromName("breathing", &m) && m == Mode::Breathing);
  TEST_ASSERT_TRUE(modeFromName("chase", &m) && m == Mode::Chase);
  TEST_ASSERT_TRUE(modeFromName("rainbow", &m) && m == Mode::Rainbow);
  TEST_ASSERT_TRUE(modeFromName("off", &m) && m == Mode::Off);
  TEST_ASSERT_FALSE(modeFromName("greeting", &m));  // transient, not settable
  TEST_ASSERT_FALSE(modeFromName("Solid", &m));
  TEST_ASSERT_FALSE(modeFromName("", &m));
  TEST_ASSERT_FALSE(modeFromName(nullptr, &m));
  TEST_ASSERT_EQUAL_STRING("chase", modeName(Mode::Chase));
}

void test_engine_greeting_overrides_then_returns_to_the_base_mode() {
  EffectEngine e;
  e.setMode(Mode::Solid);
  e.setColor(ORANGE);
  e.setBrightness(255);
  Rgb f[N];
  e.triggerGreeting(10000);
  TEST_ASSERT_TRUE(e.greetingActive(10000));
  TEST_ASSERT_EQUAL_INT((int)Mode::Greeting, (int)e.activeMode(10100));
  e.render(10250, f, N);
  TEST_ASSERT_TRUE(f[0] == (Rgb{255, 255, 255}));
  TEST_ASSERT_FALSE(e.greetingActive(10000 + EffectEngine::kGreetingMs));
  TEST_ASSERT_EQUAL_INT((int)Mode::Solid, (int)e.activeMode(10000 + EffectEngine::kGreetingMs));
  e.render(10000 + EffectEngine::kGreetingMs, f, N);
  TEST_ASSERT_TRUE(f[0] == ORANGE);
}

void test_engine_refuses_greeting_as_a_base_mode() {
  EffectEngine e;
  e.setMode(Mode::Chase);
  e.setMode(Mode::Greeting);
  TEST_ASSERT_EQUAL_INT((int)Mode::Chase, (int)e.baseMode());
}

void test_engine_brightness_scales_every_channel() {
  EffectEngine e;
  e.setMode(Mode::Solid);
  e.setColor(Rgb{200, 100, 50});
  e.setBrightness(128);
  Rgb f[4];
  e.render(0, f, 4);
  TEST_ASSERT_INT_WITHIN(1, 100, f[0].r);
  TEST_ASSERT_INT_WITHIN(1, 50, f[0].g);
  TEST_ASSERT_INT_WITHIN(1, 25, f[0].b);
  e.setBrightness(0);
  e.render(0, f, 4);
  TEST_ASSERT_EQUAL_INT(0, nonBlack(f, 4));
}

void test_engine_greeting_survives_a_millis_wrap() {
  EffectEngine e;
  e.triggerGreeting(0xFFFFFF00u);
  TEST_ASSERT_TRUE(e.greetingActive(0xFFFFFF00u + 1000));  // past the wrap
  TEST_ASSERT_FALSE(e.greetingActive(0xFFFFFF00u + 3000));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_off_is_black_and_solid_is_the_colour);
  RUN_TEST(test_breathing_swings_between_a_floor_and_the_full_colour);
  RUN_TEST(test_breathing_repeats_every_three_seconds);
  RUN_TEST(test_chase_lights_a_head_and_three_tail_pixels_that_move);
  RUN_TEST(test_chase_works_on_a_strip_shorter_than_its_tail);
  RUN_TEST(test_rainbow_spreads_the_hues_and_rotates);
  RUN_TEST(test_hsv_primaries);
  RUN_TEST(test_greeting_flashes_between_colour_and_white_then_fades_out);
  RUN_TEST(test_the_five_modes_give_five_different_frames);
  RUN_TEST(test_the_same_time_always_gives_the_same_frame);
  RUN_TEST(test_null_and_empty_buffers_are_safe);
  RUN_TEST(test_mode_names);
  RUN_TEST(test_engine_greeting_overrides_then_returns_to_the_base_mode);
  RUN_TEST(test_engine_refuses_greeting_as_a_base_mode);
  RUN_TEST(test_engine_brightness_scales_every_channel);
  RUN_TEST(test_engine_greeting_survives_a_millis_wrap);
  return UNITY_END();
}
