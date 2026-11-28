#include <math.h>
#include <string.h>
#include <unity.h>

#include "eyes.h"
#include "protocol.h"

using namespace doormat;

void setUp(void) {}
void tearDown(void) {}

static StatusView sample() {
  StatusView v;
  v.id = "mat-01";
  v.occupied = true;
  v.mode = Mode::Chase;
  v.active = Mode::Greeting;
  v.color = Rgb{0, 255, 136};
  v.brightness = 120;
  v.message = "Welcome home!";
  v.micLevel = 42;
  v.uptimeMs = 123456;
  v.steps = 7;
  v.greetings = 9;
  v.pressure = 2310;
  v.net = "sta";
  return v;
}

void test_status_has_every_field() {
  char buf[400];
  const size_t n = formatStatus(buf, sizeof(buf), sample());
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_UINT(strlen(buf), n);
  const char* want[] = {"\"t\":\"status\"", "\"id\":\"mat-01\"", "\"occupied\":true", "\"mode\":\"chase\"", "\"active\":\"greeting\"",
                        "\"color\":\"#00ff88\"", "\"brightness\":120", "\"message\":\"Welcome home!\"", "\"mic\":42",
                        "\"uptime_ms\":123456", "\"steps\":7", "\"greetings\":9", "\"pressure\":2310", "\"net\":\"sta\""};
  for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, want[i]), want[i]);
  TEST_ASSERT_EQUAL_CHAR('{', buf[0]);
  TEST_ASSERT_EQUAL_CHAR('}', buf[n - 1]);
}

void test_status_never_returns_a_cut_off_string() {
  char big[400];
  const size_t full = formatStatus(big, sizeof(big), sample());
  for (size_t cap = 1; cap <= full; cap++) {
    char small[400];
    memset(small, 'x', sizeof(small));
    TEST_ASSERT_EQUAL_UINT(0, formatStatus(small, cap, sample()));
  }
  char exact[400];
  TEST_ASSERT_EQUAL_UINT(full, formatStatus(exact, full + 1, sample()));
}

void test_status_escapes_quotes_and_backslashes_in_the_message() {
  StatusView v = sample();
  v.message = "say \"hi\" \\ bye";
  char buf[400];
  TEST_ASSERT_TRUE(formatStatus(buf, sizeof(buf), v) > 0);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"say \\\"hi\\\" \\\\ bye\""));
}

void test_status_with_no_message_and_null_strings() {
  StatusView v = sample();
  v.message = "";
  v.id = nullptr;
  v.net = nullptr;
  char buf[400];
  TEST_ASSERT_TRUE(formatStatus(buf, sizeof(buf), v) > 0);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"net\":\"none\""));
  TEST_ASSERT_EQUAL_UINT(0, formatStatus(nullptr, 10, v));
  TEST_ASSERT_EQUAL_UINT(0, formatStatus(buf, 0, v));
}

void test_json_escape() {
  char out[40];
  TEST_ASSERT_EQUAL_UINT(4, jsonEscape("a\"b", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("a\\\"b", out);
  TEST_ASSERT_EQUAL_UINT(0, jsonEscape("abcdef", out, 4));  // does not fit
  jsonEscape("a\nb\x01" "c", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("abc", out);
}

void test_presence_and_mic_events() {
  char buf[120];
  TEST_ASSERT_TRUE(formatPresenceEvent(buf, sizeof(buf), true, 5000, 3) > 0);
  TEST_ASSERT_EQUAL_STRING("{\"t\":\"presence\",\"state\":\"occupied\",\"uptime_ms\":5000,\"steps\":3}", buf);
  TEST_ASSERT_TRUE(formatPresenceEvent(buf, sizeof(buf), false, 9000, 3) > 0);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"state\":\"empty\""));
  TEST_ASSERT_TRUE(formatMicEvent(buf, sizeof(buf), 63) > 0);
  TEST_ASSERT_EQUAL_STRING("{\"t\":\"mic\",\"level\":63}", buf);
  TEST_ASSERT_EQUAL_UINT(0, formatMicEvent(buf, 5, 63));
}

void test_frame_event_samples_the_strip_evenly() {
  Rgb leds[48];
  for (int i = 0; i < 48; i++) leds[i] = Rgb{(uint8_t)i, (uint8_t)(255 - i), 0};
  char buf[300];
  TEST_ASSERT_TRUE(formatFrameEvent(buf, sizeof(buf), leds, 48, 4) > 0);
  TEST_ASSERT_EQUAL_STRING("{\"t\":\"frame\",\"n\":4,\"px\":\"00ff000cf30018e70024db00\"}", buf);
  TEST_ASSERT_TRUE(formatFrameEvent(buf, sizeof(buf), leds, 3, 10) > 0);  // more samples than pixels: one per pixel
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"n\":3"));
  TEST_ASSERT_EQUAL_UINT(0, formatFrameEvent(buf, 20, leds, 48, 4));
  TEST_ASSERT_EQUAL_UINT(0, formatFrameEvent(buf, sizeof(buf), leds, 0, 4));
  TEST_ASSERT_EQUAL_UINT(0, formatFrameEvent(buf, sizeof(buf), nullptr, 48, 4));
}

static void sine(int16_t* out, size_t n, double amp) {
  for (size_t i = 0; i < n; i++) out[i] = (int16_t)(amp * sin(2 * 3.141592653589793 * 440.0 * i / 16000.0));
}

void test_mic_level_scale() {
  int16_t s[1600];
  memset(s, 0, sizeof(s));
  TEST_ASSERT_EQUAL_UINT8(0, micLevelFromSamples(s, 1600));
  TEST_ASSERT_EQUAL_UINT8(0, micLevelFromSamples(nullptr, 10));
  TEST_ASSERT_EQUAL_UINT8(0, micLevelFromSamples(s, 0));
  for (int i = 0; i < 1600; i++) s[i] = (i & 1) ? 32767 : -32768;  // full scale square wave
  TEST_ASSERT_EQUAL_UINT8(100, micLevelFromSamples(s, 1600));
  for (int i = 0; i < 1600; i++) s[i] = (i & 1) ? 3277 : -3277;    // 0.1 of full scale = -20 dB
  TEST_ASSERT_UINT8_WITHIN(1, 67, micLevelFromSamples(s, 1600));
  for (int i = 0; i < 1600; i++) s[i] = (i & 1) ? 58 : -58;        // about -55 dB: just above the floor
  TEST_ASSERT_UINT8_WITHIN(1, 8, micLevelFromSamples(s, 1600));
  for (int i = 0; i < 1600; i++) s[i] = (i & 1) ? 20 : -20;        // -64 dB: below the floor
  TEST_ASSERT_EQUAL_UINT8(0, micLevelFromSamples(s, 1600));
}

void test_mic_level_rises_with_amplitude_and_ignores_dc_free_sign() {
  int16_t s[1600];
  uint8_t last = 0;
  for (double amp = 50; amp < 32000; amp *= 1.5) {
    sine(s, 1600, amp);
    const uint8_t lv = micLevelFromSamples(s, 1600);
    TEST_ASSERT_TRUE(lv >= last);
    last = lv;
  }
  TEST_ASSERT_TRUE(last > 85);
  sine(s, 1600, 8000);
  const uint8_t a = micLevelFromSamples(s, 1600);
  for (int i = 0; i < 1600; i++) s[i] = (int16_t)-s[i];
  TEST_ASSERT_EQUAL_UINT8(a, micLevelFromSamples(s, 1600));
}

void test_mjpeg_part_header() {
  char buf[120];
  const size_t n = mjpegPartHeader(buf, sizeof(buf), 12345);
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_STRING("\r\n--doormatframe\r\nContent-Type: image/jpeg\r\nContent-Length: 12345\r\n\r\n", buf);
  TEST_ASSERT_EQUAL_UINT(0, mjpegPartHeader(buf, 20, 12345));
  TEST_ASSERT_EQUAL_UINT(0, mjpegPartHeader(buf, sizeof(buf), 0));
}

void test_bmp_of_the_eye_buffer() {
  uint8_t fb[kEyeBytes];
  memset(fb, 0, sizeof(fb));
  fb[0] = 0x80;  // top left pixel white
  uint8_t bmp[1200];
  const size_t n = framebufferToBmp1bpp(fb, kEyeW, kEyeH, bmp, sizeof(bmp));
  TEST_ASSERT_EQUAL_UINT(14 + 40 + 8 + 16 * kEyeH, n);
  TEST_ASSERT_EQUAL_CHAR('B', bmp[0]);
  TEST_ASSERT_EQUAL_CHAR('M', bmp[1]);
  TEST_ASSERT_EQUAL_UINT8(n & 0xFF, bmp[2]);
  TEST_ASSERT_EQUAL_UINT8(kEyeW, bmp[18]);
  TEST_ASSERT_EQUAL_UINT8(kEyeH, bmp[22]);
  TEST_ASSERT_EQUAL_UINT8(1, bmp[28]);
  // BMP rows are bottom up, so the top row of the picture is the last row in the file.
  TEST_ASSERT_EQUAL_UINT8(0x80, bmp[62 + 16 * (kEyeH - 1)]);
  TEST_ASSERT_EQUAL_UINT8(0x00, bmp[62]);
  TEST_ASSERT_EQUAL_UINT(0, framebufferToBmp1bpp(fb, kEyeW, kEyeH, bmp, n - 1));
  TEST_ASSERT_EQUAL_UINT(0, framebufferToBmp1bpp(fb, 100, kEyeH, bmp, sizeof(bmp)));  // width must be a multiple of 8
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_status_has_every_field);
  RUN_TEST(test_status_never_returns_a_cut_off_string);
  RUN_TEST(test_status_escapes_quotes_and_backslashes_in_the_message);
  RUN_TEST(test_status_with_no_message_and_null_strings);
  RUN_TEST(test_json_escape);
  RUN_TEST(test_presence_and_mic_events);
  RUN_TEST(test_frame_event_samples_the_strip_evenly);
  RUN_TEST(test_mic_level_scale);
  RUN_TEST(test_mic_level_rises_with_amplitude_and_ignores_dc_free_sign);
  RUN_TEST(test_mjpeg_part_header);
  RUN_TEST(test_bmp_of_the_eye_buffer);
  return UNITY_END();
}
