#include <stdio.h>
#include <string.h>
#include <unity.h>

#include "command.h"

using namespace doormat;

void setUp(void) {}
void tearDown(void) {}

static ParseError parse(const char* route, const char* body, Command* c) { return parseCommand(route, body, body ? strlen(body) : 0, c); }

void test_hex_colours() {
  Rgb c;
  TEST_ASSERT_TRUE(parseHexColor("#ff8800", &c));
  TEST_ASSERT_TRUE(c == (Rgb{255, 136, 0}));
  TEST_ASSERT_TRUE(parseHexColor("00FFaa", &c));
  TEST_ASSERT_TRUE(c == (Rgb{0, 255, 170}));
  TEST_ASSERT_FALSE(parseHexColor("#ff88", &c));
  TEST_ASSERT_FALSE(parseHexColor("#ff88000", &c));
  TEST_ASSERT_FALSE(parseHexColor("#gg0000", &c));
  TEST_ASSERT_FALSE(parseHexColor("##ff8800", &c));
  TEST_ASSERT_FALSE(parseHexColor("", &c));
  TEST_ASSERT_FALSE(parseHexColor(nullptr, &c));
}

void test_greet_and_status_need_no_fields() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("greet", "", &c));
  TEST_ASSERT_EQUAL_INT((int)CmdType::Greet, (int)c.type);
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("greet", nullptr, &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("status", "{}", &c));
  TEST_ASSERT_EQUAL_INT((int)CmdType::Status, (int)c.type);
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse(nullptr, "{\"cmd\":\"greet\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)CmdType::Greet, (int)c.type);
}

void test_led_with_all_three_fields() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("led", "{\"mode\":\"chase\",\"color\":\"#00ff88\",\"brightness\":120}", &c));
  TEST_ASSERT_EQUAL_INT((int)CmdType::Led, (int)c.type);
  TEST_ASSERT_TRUE(c.hasMode && c.mode == Mode::Chase);
  TEST_ASSERT_TRUE(c.hasColor && c.color == (Rgb{0, 255, 136}));
  TEST_ASSERT_TRUE(c.hasBrightness && c.brightness == 120);
}

void test_led_with_one_field_only_sets_that_field() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("led", "{\"mode\":\"rainbow\"}", &c));
  TEST_ASSERT_TRUE(c.hasMode && !c.hasColor && !c.hasBrightness);
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("led", "{\"brightness\":0}", &c));
  TEST_ASSERT_TRUE(c.hasBrightness && c.brightness == 0 && !c.hasMode);
}

void test_led_rejections() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::MissingField, (int)parse("led", "{}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::MissingField, (int)parse("led", "", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadMode, (int)parse("led", "{\"mode\":\"strobe\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadMode, (int)parse("led", "{\"mode\":\"greeting\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadMode, (int)parse("led", "{\"mode\":3}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadColor, (int)parse("led", "{\"color\":\"red\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadColor, (int)parse("led", "{\"color\":5}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadBrightness, (int)parse("led", "{\"brightness\":256}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadBrightness, (int)parse("led", "{\"brightness\":-1}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadBrightness, (int)parse("led", "{\"brightness\":\"200\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::NotJson, (int)parse("led", "{\"brightness\":1.5}", &c));
}

void test_a_rejected_command_leaves_nothing_usable() {
  Command c;
  parse("led", "{\"mode\":\"chase\",\"color\":\"zzz\"}", &c);
  TEST_ASSERT_EQUAL_INT((int)CmdType::None, (int)c.type);
}

void test_message_by_text_and_by_index() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("message", "{\"text\":\"  Mind the step \"}", &c));
  TEST_ASSERT_TRUE(c.hasText);
  TEST_ASSERT_EQUAL_STRING("Mind the step", c.text);
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("message", "{\"index\":3}", &c));
  TEST_ASSERT_TRUE(c.hasIndex && c.index == 3);
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("message", "{\"text\":\"say \\\"hi\\\"\"}", &c));
  TEST_ASSERT_EQUAL_STRING("say \"hi\"", c.text);
}

void test_message_rejections() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::MissingField, (int)parse("message", "{}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadText, (int)parse("message", "{\"text\":\"   \"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadText, (int)parse("message", "{\"text\":5}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadText, (int)parse("message", "{\"text\":\"a\",\"index\":1}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadIndex, (int)parse("message", "{\"index\":8}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadIndex, (int)parse("message", "{\"index\":-1}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadIndex, (int)parse("message", "{\"index\":\"1\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::NotJson, (int)parse("message", "{\"text\":\"\\u0041\"}", &c));  // \u is refused outright
}

void test_a_long_text_is_cut_not_overflowed() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("message", "{\"text\":\"0123456789012345678901234567890123456789\"}", &c));
  TEST_ASSERT_EQUAL_UINT(32, strlen(c.text));
  char big[100];
  strcpy(big, "{\"text\":\"");
  for (int i = 0; i < 70; i++) strcat(big, "x");
  strcat(big, "\"}");
  TEST_ASSERT_EQUAL_INT((int)ParseError::TooLong, (int)parse("message", big, &c));  // a 70 character string does not fit a field at all
}

void test_wifi_credentials() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("wifi", "{\"ssid\":\"home\",\"pass\":\"correct horse\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)CmdType::Wifi, (int)c.type);
  TEST_ASSERT_EQUAL_STRING("home", c.ssid);
  TEST_ASSERT_EQUAL_STRING("correct horse", c.pass);
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("wifi", "{\"ssid\":\"open net\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadWifi, (int)parse("wifi", "{\"ssid\":\"home\",\"pass\":\"short\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadWifi, (int)parse("wifi", "{\"ssid\":\"\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::BadWifi, (int)parse("wifi", "{\"ssid\":\"012345678901234567890123456789012\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::MissingField, (int)parse("wifi", "{\"pass\":\"password1\"}", &c));
}

void test_the_route_wins_over_a_cmd_field_in_the_body() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("led", "{\"cmd\":\"greet\",\"mode\":\"solid\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)CmdType::Led, (int)c.type);
}

void test_the_cmd_field_is_needed_without_a_route() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::MissingField, (int)parse(nullptr, "{\"mode\":\"solid\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::Empty, (int)parse(nullptr, "", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::UnknownCmd, (int)parse(nullptr, "{\"cmd\":\"reboot\"}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::UnknownCmd, (int)parse("format", "{}", &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::MissingField, (int)parse(nullptr, "{\"cmd\":5}", &c));
}

void test_a_value_that_looks_like_a_command_is_just_a_value() {
  Command c;
  // The first colour is the real one; the decoy inside the text must not be read as a key.
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("message", "{\"text\":\"{\\\"index\\\":2}\"}", &c));
  TEST_ASSERT_TRUE(c.hasText && !c.hasIndex);
}

void test_json_shape_errors() {
  Command c;
  const char* bad[] = {"not json", "[]", "{", "}", "{\"mode\"}", "{\"mode\":}", "{\"mode\":\"solid\"", "{\"mode\":\"solid\",}",
                       "{\"mode\":\"solid\"} trailing", "{\"a\":{\"b\":1}}", "{\"a\":[1]}", "{\"a\":null}", "{mode:\"solid\"}",
                       "{\"mode\":\"sol", "{\"mode\":\"so\\"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    TEST_ASSERT_TRUE(parse("led", bad[i], &c) != ParseError::Ok);
    TEST_ASSERT_EQUAL_INT((int)CmdType::None, (int)c.type);
  }
}

void test_whitespace_is_allowed_and_extra_keys_are_ignored() {
  Command c;
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("led", " \r\n{ \"mode\" : \"solid\" , \"extra\" : true , \"n\" : 5 } \n", &c));
  TEST_ASSERT_TRUE(c.hasMode);
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parse("led", "{\"mode\":\"solid\",\"a_very_long_key_name\":1}", &c));
}

void test_size_limits() {
  Command c;
  char body[400];
  memset(body, ' ', sizeof(body));
  body[sizeof(body) - 1] = '\0';
  TEST_ASSERT_EQUAL_INT((int)ParseError::TooLong, (int)parseCommand("greet", body, 300, &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::Ok, (int)parseCommand("greet", body, 256, &c));
  TEST_ASSERT_EQUAL_INT((int)ParseError::TooLong,
                        (int)parse("led", "{\"a\":1,\"b\":1,\"c\":1,\"d\":1,\"e\":1,\"f\":1,\"g\":1,\"h\":1,\"mode\":\"solid\"}", &c));
}

void test_a_null_output_does_not_crash() { TEST_ASSERT_TRUE(parseCommand("greet", "", 0, nullptr) != ParseError::Ok); }

// Seeded fuzz: arbitrary bytes and mutated valid bodies must never crash and never produce a type the route does not name.
void test_fuzz_random_bytes_and_mutations() {
  uint32_t seed = 99;
  auto rnd = [&seed]() {
    seed = seed * 1664525u + 1013904223u;
    return seed >> 8;
  };
  const char* valid[] = {"{\"mode\":\"chase\",\"color\":\"#ff8800\",\"brightness\":200}", "{\"text\":\"hello there\"}", "{\"index\":2}",
                         "{\"ssid\":\"home\",\"pass\":\"password1\"}", "{}"};
  const char* routes[] = {"led", "message", "message", "wifi", "greet"};
  const CmdType types[] = {CmdType::Led, CmdType::Message, CmdType::Message, CmdType::Wifi, CmdType::Greet};
  int accepted = 0;
  for (int i = 0; i < 20000; i++) {
    char buf[300];
    size_t len;
    const size_t which = rnd() % 5;
    if (i % 2 == 0) {
      len = rnd() % 120;
      for (size_t k = 0; k < len; k++) buf[k] = (char)(rnd() & 0xFF);
    } else {
      len = strlen(valid[which]);
      memcpy(buf, valid[which], len);
      const int edits = 1 + (int)(rnd() % 3);
      for (int e = 0; e < edits; e++) buf[rnd() % len] = (char)(32 + rnd() % 95);
    }
    Command c;
    const ParseError pe = parseCommand(routes[which], buf, len, &c);
    if (pe == ParseError::Ok) {
      accepted++;
      TEST_ASSERT_EQUAL_INT((int)types[which], (int)c.type);
      if (c.type == CmdType::Message && c.hasText) {
        TEST_ASSERT_TRUE(strlen(c.text) >= 1 && strlen(c.text) <= 32);
        for (const char* p = c.text; *p; p++) TEST_ASSERT_TRUE(*p >= 0x20 && *p <= 0x7E);
      }
      if (c.type == CmdType::Led && c.hasBrightness) TEST_ASSERT_TRUE(c.brightness <= 255);
    } else {
      TEST_ASSERT_EQUAL_INT((int)CmdType::None, (int)c.type);
    }
  }
  TEST_ASSERT_TRUE(accepted > 0);
}

void test_error_names_are_distinct_and_non_empty() {
  const char* seen[16];
  int n = 0;
  for (int e = 0; e <= (int)ParseError::BadWifi; e++) {
    const char* name = errorName((ParseError)e);
    TEST_ASSERT_TRUE(strlen(name) > 0);
    for (int j = 0; j < n; j++) TEST_ASSERT_TRUE(strcmp(seen[j], name) != 0);
    seen[n++] = name;
  }
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_hex_colours);
  RUN_TEST(test_greet_and_status_need_no_fields);
  RUN_TEST(test_led_with_all_three_fields);
  RUN_TEST(test_led_with_one_field_only_sets_that_field);
  RUN_TEST(test_led_rejections);
  RUN_TEST(test_a_rejected_command_leaves_nothing_usable);
  RUN_TEST(test_message_by_text_and_by_index);
  RUN_TEST(test_message_rejections);
  RUN_TEST(test_a_long_text_is_cut_not_overflowed);
  RUN_TEST(test_wifi_credentials);
  RUN_TEST(test_the_route_wins_over_a_cmd_field_in_the_body);
  RUN_TEST(test_the_cmd_field_is_needed_without_a_route);
  RUN_TEST(test_a_value_that_looks_like_a_command_is_just_a_value);
  RUN_TEST(test_json_shape_errors);
  RUN_TEST(test_whitespace_is_allowed_and_extra_keys_are_ignored);
  RUN_TEST(test_size_limits);
  RUN_TEST(test_a_null_output_does_not_crash);
  RUN_TEST(test_fuzz_random_bytes_and_mutations);
  RUN_TEST(test_error_names_are_distinct_and_non_empty);
  return UNITY_END();
}
