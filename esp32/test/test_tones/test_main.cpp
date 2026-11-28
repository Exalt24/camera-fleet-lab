#include <stdlib.h>
#include <unity.h>

#include "tones.h"

using namespace doormat;

void setUp(void) {}
void tearDown(void) {}

static const uint32_t RATE = 16000;

void test_the_greeting_has_four_rising_notes_and_a_length() {
  TEST_ASSERT_EQUAL_UINT(4, greetingNoteCount());
  for (size_t i = 1; i < greetingNoteCount(); i++) TEST_ASSERT_TRUE(greetingNote(i).freqHz > greetingNote(i - 1).freqHz);
  TEST_ASSERT_EQUAL_UINT32(650, greetingTotalMs());
}

void test_samples_stay_inside_the_requested_amplitude() {
  const size_t n = RATE * greetingTotalMs() / 1000;
  int16_t* pcm = (int16_t*)malloc(n * sizeof(int16_t));
  renderGreetingPcm(pcm, n, 0, RATE, 8000);
  int peak = 0;
  for (size_t i = 0; i < n; i++) peak = abs(pcm[i]) > peak ? abs(pcm[i]) : peak;
  free(pcm);
  TEST_ASSERT_TRUE(peak > 7000 && peak <= 8000);
}

void test_zero_amplitude_and_negative_amplitude_are_silent() {
  int16_t pcm[800];
  renderGreetingPcm(pcm, 800, 800, RATE, 0);
  for (int i = 0; i < 800; i++) TEST_ASSERT_EQUAL_INT16(0, pcm[i]);
  renderGreetingPcm(pcm, 800, 800, RATE, -5);
  for (int i = 0; i < 800; i++) TEST_ASSERT_EQUAL_INT16(0, pcm[i]);
}

void test_the_sound_starts_silent_and_ends_in_silence() {
  int16_t pcm[64];
  renderGreetingPcm(pcm, 64, 0, RATE, 20000);
  TEST_ASSERT_EQUAL_INT16(0, pcm[0]);  // the fade in starts at zero, so there is no click
  for (int i = 0; i < 12; i++) TEST_ASSERT_TRUE(abs(pcm[i]) < 2000);  // and rises over 10 ms instead of jumping
  const uint32_t end = RATE * greetingTotalMs() / 1000;
  renderGreetingPcm(pcm, 64, end, RATE, 20000);
  for (int i = 0; i < 64; i++) TEST_ASSERT_EQUAL_INT16(0, pcm[i]);
  renderGreetingPcm(pcm, 64, end + 100000, RATE, 20000);
  for (int i = 0; i < 64; i++) TEST_ASSERT_EQUAL_INT16(0, pcm[i]);
}

void test_the_first_note_has_the_right_pitch() {
  // Count rising zero crossings across the first note (130 ms): frequency * 0.130 s.
  const size_t n = RATE * 130 / 1000;
  int16_t* pcm = (int16_t*)malloc(n * sizeof(int16_t));
  renderGreetingPcm(pcm, n, 0, RATE, 10000);
  int crossings = 0;
  for (size_t i = 1; i < n; i++)
    if (pcm[i - 1] < 0 && pcm[i] >= 0) crossings++;
  free(pcm);
  TEST_ASSERT_INT_WITHIN(2, 523 * 130 / 1000, crossings);
}

void test_a_chunked_render_equals_one_big_render() {
  const size_t n = 4000;
  int16_t* whole = (int16_t*)malloc(n * sizeof(int16_t));
  int16_t* parts = (int16_t*)malloc(n * sizeof(int16_t));
  renderGreetingPcm(whole, n, 123, RATE, 9000);
  for (size_t off = 0; off < n; off += 256) renderGreetingPcm(parts + off, (n - off) < 256 ? (n - off) : 256, 123 + off, RATE, 9000);
  for (size_t i = 0; i < n; i++) TEST_ASSERT_EQUAL_INT16(whole[i], parts[i]);
  free(whole);
  free(parts);
}

void test_null_and_empty_are_safe() {
  renderGreetingPcm(nullptr, 10, 0, RATE, 100);
  int16_t x = 77;
  renderGreetingPcm(&x, 0, 0, RATE, 100);
  TEST_ASSERT_EQUAL_INT16(77, x);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_greeting_has_four_rising_notes_and_a_length);
  RUN_TEST(test_samples_stay_inside_the_requested_amplitude);
  RUN_TEST(test_zero_amplitude_and_negative_amplitude_are_silent);
  RUN_TEST(test_the_sound_starts_silent_and_ends_in_silence);
  RUN_TEST(test_the_first_note_has_the_right_pitch);
  RUN_TEST(test_a_chunked_render_equals_one_big_render);
  RUN_TEST(test_null_and_empty_are_safe);
  return UNITY_END();
}
