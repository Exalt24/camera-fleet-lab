#include <string.h>
#include <unity.h>

#include "eyes.h"

using namespace doormat;

void setUp(void) {}
void tearDown(void) {}

static bool px(const uint8_t* fb, int x, int y) { return (fb[y * (kEyeW / 8) + x / 8] >> (7 - (x & 7))) & 1; }

static int litCount(const uint8_t* fb) {
  int c = 0;
  for (int y = 0; y < kEyeH; y++)
    for (int x = 0; x < kEyeW; x++) c += px(fb, x, y);
  return c;
}

void test_the_eyes_blink_within_five_seconds_and_open_again() {
  EyeAnimator a(7);
  uint8_t minOpen = 100;
  bool reopened = false;
  for (uint32_t t = 0; t < 6000; t += 10) {
    const EyeFrame f = a.frame(t);
    TEST_ASSERT_TRUE(f.open <= 100);
    if (f.open < minOpen) minOpen = f.open;
    if (minOpen < 20 && f.open == 100) reopened = true;
  }
  TEST_ASSERT_TRUE(minOpen < 20);
  TEST_ASSERT_TRUE(reopened);
}

void test_blinks_are_not_back_to_back() {
  EyeAnimator a(3);
  int blinks = 0;
  bool inBlink = false;
  for (uint32_t t = 0; t < 60000; t += 10) {
    const EyeFrame f = a.frame(t);
    if (f.open < 50 && !inBlink) {
      blinks++;
      inBlink = true;
    }
    if (f.open == 100) inBlink = false;
  }
  // Every 2 to 5 seconds plus the blink itself: between 10 and 30 in a minute.
  TEST_ASSERT_TRUE(blinks >= 10 && blinks <= 30);
}

void test_the_same_seed_gives_the_same_eyes_and_another_seed_does_not() {
  EyeAnimator a(11), b(11), c(12);
  bool differs = false;
  for (uint32_t t = 0; t < 20000; t += 20) {
    const EyeFrame fa = a.frame(t), fb = b.frame(t), fc = c.frame(t);
    TEST_ASSERT_TRUE(fa.open == fb.open && fa.gazeX == fb.gazeX && fa.gazeY == fb.gazeY);
    if (fa.open != fc.open || fa.gazeX != fc.gazeX || fa.gazeY != fc.gazeY) differs = true;
  }
  TEST_ASSERT_TRUE(differs);
}

void test_gaze_stays_inside_the_eye() {
  EyeAnimator a(5);
  for (uint32_t t = 0; t < 120000; t += 50) {
    const EyeFrame f = a.frame(t);
    TEST_ASSERT_TRUE(f.gazeX >= -6 && f.gazeX <= 6);
    TEST_ASSERT_TRUE(f.gazeY >= -3 && f.gazeY <= 3);
  }
}

void test_happy_lasts_until_the_given_time() {
  EyeAnimator a(1);
  a.setHappy(5000, 1000);
  TEST_ASSERT_EQUAL_INT((int)Expression::Happy, (int)a.frame(1000).expr);
  TEST_ASSERT_EQUAL_INT((int)Expression::Happy, (int)a.frame(4999).expr);
  TEST_ASSERT_EQUAL_INT((int)Expression::Idle, (int)a.frame(5000).expr);
  TEST_ASSERT_EQUAL_INT((int)Expression::Idle, (int)a.frame(6000).expr);
}

void test_open_eyes_are_white_with_a_dark_pupil() {
  uint8_t fb[kEyeBytes];
  renderEyes(EyeFrame{100, 0, 0, Expression::Idle}, fb);
  TEST_ASSERT_TRUE(px(fb, 34 - 15, 24));   // white of the left eye
  TEST_ASSERT_FALSE(px(fb, 34, 24));       // pupil at the centre
  TEST_ASSERT_TRUE(px(fb, 94 + 15, 24));   // white of the right eye
  TEST_ASSERT_FALSE(px(fb, 94, 24));
  TEST_ASSERT_FALSE(px(fb, 64, 24));       // nothing between the eyes
  TEST_ASSERT_FALSE(px(fb, 2, 2));         // the corners stay dark
}

void test_the_pupil_follows_the_gaze() {
  uint8_t a[kEyeBytes], b[kEyeBytes];
  renderEyes(EyeFrame{100, -6, 0, Expression::Idle}, a);
  renderEyes(EyeFrame{100, 6, 0, Expression::Idle}, b);
  TEST_ASSERT_FALSE(px(a, 34 - 6, 24));
  TEST_ASSERT_TRUE(px(a, 34 + 6, 24));
  TEST_ASSERT_TRUE(px(b, 34 - 6, 24));
  TEST_ASSERT_FALSE(px(b, 34 + 6, 24));
}

void test_a_closing_eye_loses_pixels_and_a_closed_one_is_a_thin_line() {
  uint8_t fb[kEyeBytes];
  renderEyes(EyeFrame{100, 0, 0, Expression::Idle}, fb);
  const int open = litCount(fb);
  renderEyes(EyeFrame{50, 0, 0, Expression::Idle}, fb);
  const int half = litCount(fb);
  renderEyes(EyeFrame{0, 0, 0, Expression::Idle}, fb);
  const int shut = litCount(fb);
  TEST_ASSERT_TRUE(open > half && half > shut);
  TEST_ASSERT_TRUE(shut > 0 && shut < 200);
}

void test_happy_eyes_have_no_lower_half_and_a_cut_out_arch() {
  uint8_t fb[kEyeBytes];
  renderEyes(EyeFrame{100, 0, 0, Expression::Happy}, fb);
  for (int x = 0; x < kEyeW; x++) TEST_ASSERT_FALSE(px(fb, x, 30));
  TEST_ASSERT_TRUE(px(fb, 34, 7));  // the arch is lit on top
  uint8_t idle[kEyeBytes];
  renderEyes(EyeFrame{100, 0, 0, Expression::Idle}, idle);
  TEST_ASSERT_TRUE(memcmp(fb, idle, sizeof(fb)) != 0);
}

void test_extreme_frames_stay_inside_the_buffer() {
  uint8_t guard[kEyeBytes + 16];
  memset(guard, 0xAA, sizeof(guard));
  renderEyes(EyeFrame{100, 127, 127, Expression::Idle}, guard);
  renderEyes(EyeFrame{100, -128, -128, Expression::Happy}, guard);
  for (size_t i = kEyeBytes; i < sizeof(guard); i++) TEST_ASSERT_EQUAL_UINT8(0xAA, guard[i]);
  renderEyes(EyeFrame{100, 0, 0, Expression::Idle}, nullptr);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_eyes_blink_within_five_seconds_and_open_again);
  RUN_TEST(test_blinks_are_not_back_to_back);
  RUN_TEST(test_the_same_seed_gives_the_same_eyes_and_another_seed_does_not);
  RUN_TEST(test_gaze_stays_inside_the_eye);
  RUN_TEST(test_happy_lasts_until_the_given_time);
  RUN_TEST(test_open_eyes_are_white_with_a_dark_pupil);
  RUN_TEST(test_the_pupil_follows_the_gaze);
  RUN_TEST(test_a_closing_eye_loses_pixels_and_a_closed_one_is_a_thin_line);
  RUN_TEST(test_happy_eyes_have_no_lower_half_and_a_cut_out_arch);
  RUN_TEST(test_extreme_frames_stay_inside_the_buffer);
  return UNITY_END();
}
