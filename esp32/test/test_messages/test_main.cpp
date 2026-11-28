#include <string.h>
#include <unity.h>

#include "messages.h"

using namespace doormat;

void setUp(void) {}
void tearDown(void) {}

void test_there_are_at_least_four_default_messages() {
  MessageScheduler m;
  TEST_ASSERT_TRUE(m.count() >= 4);
  for (size_t i = 0; i < m.count(); i++) TEST_ASSERT_TRUE(strlen(m.at(i)) > 0);
  TEST_ASSERT_EQUAL_STRING("", m.at(m.count()));  // out of range is an empty string, not garbage
}

void test_nothing_is_shown_before_the_first_greeting() {
  MessageScheduler m;
  TEST_ASSERT_EQUAL_STRING("", m.current(0));
  TEST_ASSERT_EQUAL_STRING("", m.current(123456));
}

void test_greetings_walk_the_list_in_order_and_wrap() {
  MessageScheduler m;
  const size_t n = m.count();
  for (size_t round = 0; round < 2; round++) {
    for (size_t i = 0; i < n; i++) {
      const uint32_t t = 1000 + (uint32_t)(round * n + i) * 10000;
      m.onGreeting(t);
      TEST_ASSERT_EQUAL_STRING(m.at(i), m.current(t));
    }
  }
}

void test_a_message_goes_away_after_the_hold_time() {
  MessageScheduler m;
  m.onGreeting(1000);
  TEST_ASSERT_TRUE(strlen(m.current(1000 + MessageScheduler::kHoldMs - 1)) > 0);
  TEST_ASSERT_EQUAL_STRING("", m.current(1000 + MessageScheduler::kHoldMs));
}

void test_a_message_survives_a_millis_wrap() {
  MessageScheduler m;
  m.onGreeting(0xFFFFFF00u);
  TEST_ASSERT_TRUE(strlen(m.current(0xFFFFFF00u + 1000)) > 0);
  TEST_ASSERT_EQUAL_STRING("", m.current(0xFFFFFF00u + 7000));
}

void test_sanitize_keeps_printable_ascii_only() {
  char out[33];
  TEST_ASSERT_EQUAL_UINT(5, sanitizeText("Hello", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("Hello", out);
  TEST_ASSERT_EQUAL_UINT(3, sanitizeText("a\x01" "b\x7f" "c\xc3\xa9", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("abc", out);
}

void test_sanitize_trims_and_collapses_spaces() {
  char out[33];
  sanitizeText("   many    spaces   here   ", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("many spaces here", out);
  TEST_ASSERT_EQUAL_UINT(0, sanitizeText("     ", out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT(0, sanitizeText("\n\t\x01", out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT(0, sanitizeText(nullptr, out, sizeof(out)));
}

void test_sanitize_never_writes_past_the_buffer() {
  char out[8];
  const size_t n = sanitizeText("0123456789", out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT(7, n);
  TEST_ASSERT_EQUAL_STRING("0123456", out);
  char tiny[1];
  TEST_ASSERT_EQUAL_UINT(0, sanitizeText("abc", tiny, 1));
  TEST_ASSERT_EQUAL_UINT(0, sanitizeText("abc", nullptr, 0));
}

void test_add_respects_the_limit_and_the_length() {
  MessageScheduler m;
  while (m.count() < MessageScheduler::kMaxMessages) TEST_ASSERT_TRUE(m.add("another"));
  TEST_ASSERT_FALSE(m.add("one too many"));
  TEST_ASSERT_EQUAL_UINT(MessageScheduler::kMaxMessages, m.count());
  MessageScheduler m2;
  TEST_ASSERT_FALSE(m2.add("   "));
  TEST_ASSERT_TRUE(m2.add("0123456789012345678901234567890123456789"));  // 40 chars: kept, cut to 32
  TEST_ASSERT_EQUAL_UINT(MessageScheduler::kMaxLen, strlen(m2.at(m2.count() - 1)));
}

void test_select_shows_that_message_and_continues_after_it() {
  MessageScheduler m;
  TEST_ASSERT_TRUE(m.select(2, 500));
  TEST_ASSERT_EQUAL_STRING(m.at(2), m.current(500));
  m.onGreeting(20000);
  TEST_ASSERT_EQUAL_STRING(m.at(3), m.current(20000));
  TEST_ASSERT_FALSE(m.select(m.count(), 30000));
  TEST_ASSERT_FALSE(m.select(200, 30000));
}

void test_custom_text_is_shown_and_does_not_enter_the_list() {
  MessageScheduler m;
  const size_t before = m.count();
  TEST_ASSERT_TRUE(m.showCustom("  Mind the step  ", 100));
  TEST_ASSERT_EQUAL_STRING("Mind the step", m.current(100));
  TEST_ASSERT_EQUAL_UINT(before, m.count());
  TEST_ASSERT_FALSE(m.showCustom("   ", 200));
  TEST_ASSERT_EQUAL_STRING("Mind the step", m.current(200));  // a refused text leaves the old one alone
}

void test_rotation_happens_only_while_occupied() {
  MessageScheduler m;
  m.onGreeting(1000);
  const char* first = m.current(1000);
  char firstCopy[40];
  strcpy(firstCopy, first);
  m.tick(1000 + MessageScheduler::kRotateMs - 1, true);
  TEST_ASSERT_EQUAL_STRING(firstCopy, m.current(1000 + MessageScheduler::kRotateMs - 1));
  m.tick(1000 + MessageScheduler::kRotateMs, true);
  TEST_ASSERT_TRUE(strcmp(firstCopy, m.current(1000 + MessageScheduler::kRotateMs)) != 0);

  MessageScheduler idle;
  idle.onGreeting(1000);
  strcpy(firstCopy, idle.current(1000));
  idle.tick(1000 + MessageScheduler::kRotateMs + 500, false);
  TEST_ASSERT_EQUAL_STRING(firstCopy, idle.current(1000 + MessageScheduler::kRotateMs + 500));
}

void test_rotation_does_nothing_before_any_message_was_shown() {
  MessageScheduler m;
  m.tick(50000, true);
  TEST_ASSERT_EQUAL_STRING("", m.current(50000));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_there_are_at_least_four_default_messages);
  RUN_TEST(test_nothing_is_shown_before_the_first_greeting);
  RUN_TEST(test_greetings_walk_the_list_in_order_and_wrap);
  RUN_TEST(test_a_message_goes_away_after_the_hold_time);
  RUN_TEST(test_a_message_survives_a_millis_wrap);
  RUN_TEST(test_sanitize_keeps_printable_ascii_only);
  RUN_TEST(test_sanitize_trims_and_collapses_spaces);
  RUN_TEST(test_sanitize_never_writes_past_the_buffer);
  RUN_TEST(test_add_respects_the_limit_and_the_length);
  RUN_TEST(test_select_shows_that_message_and_continues_after_it);
  RUN_TEST(test_custom_text_is_shown_and_does_not_enter_the_list);
  RUN_TEST(test_rotation_happens_only_while_occupied);
  RUN_TEST(test_rotation_does_nothing_before_any_message_was_shown);
  return UNITY_END();
}
